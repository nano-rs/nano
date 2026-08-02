// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for the health scheduler notification builders.

use super::*;
use crate::health::types::FeedStalenessStatus;
use uuid::Uuid;

/// NAN-1933: a data-feed-stale notification must link to the real
/// `/ingestion/log-sources/<lsrc typeid>` route. The old builder emitted
/// `/log-sources/<raw-uuid>`, which 404s (wrong path prefix AND a raw UUID
/// instead of the `lsrc` typeid the route resolves).
#[test]
fn feed_stale_notification_links_to_ingestion_log_source_route() {
    // The exact UUID from the bug report.
    let feed_id = Uuid::parse_str("61321828-ed33-47fa-9701-e2d960573446").unwrap();
    let status = FeedStalenessStatus {
        feed_id,
        feed_name: "apache".to_string(),
        last_event_at: None,
        stale_threshold_minutes: 30,
        minutes_since_last_event: Some(45),
        is_stale: true,
    };

    let notification = HealthScheduler::feed_stale_notification(&status);
    let link = notification
        .link
        .expect("stale-feed notification must carry a link");

    assert!(
        link.starts_with("/ingestion/log-sources/lsrc_"),
        "link must target the log-source detail route with an lsrc typeid, got: {link}"
    );

    // The typeid in the link must round-trip back to the original log_sources.id
    // — guards against both a wrong prefix and the wrong id being encoded.
    let typeid = link
        .strip_prefix("/ingestion/log-sources/")
        .expect("link has the expected prefix");
    let decoded = crate::typeid::decode(crate::typeid::log_source::PREFIX, typeid)
        .expect("link suffix must be a valid lsrc typeid");
    assert_eq!(
        decoded, feed_id,
        "the typeid must decode back to the original feed_id"
    );
}

/// NAN-2282: the existing feed monitor is also the producer for the durable
/// health bus. The stale and healthy branches must address the exact same
/// lifecycle key so a recovery closes (and externally resolves) the incident
/// instead of opening a second notification stream.
#[test]
fn feed_stale_and_recovery_share_stable_health_lifecycle() {
    let feed_id = Uuid::parse_str("61321828-ed33-47fa-9701-e2d960573446").unwrap();
    let status = FeedStalenessStatus {
        feed_id,
        feed_name: "apache".to_string(),
        last_event_at: None,
        stale_threshold_minutes: 30,
        minutes_since_last_event: Some(45),
        is_stale: true,
    };

    let event = HealthScheduler::feed_stale_health_event(&status);
    let recovery_key = HealthScheduler::feed_stale_dedup_key(feed_id);

    assert_eq!(event.dedup_key, recovery_key);
    assert_eq!(event.dedup_key, format!("log_source:{feed_id}:stale"));
    assert_eq!(event.category, crate::system_health::HealthCategory::LogSource);
    assert_eq!(event.resource_type, "log_source");
    assert_eq!(event.resource_id, Some(feed_id.to_string()));
}

/// NAN-2277: the stuck-query notification must name the query, how long it has
/// been running since cancellation, and the remedy (server restart), and its
/// metadata must carry the literal-stripped snippet for triage.
#[test]
fn stuck_query_notification_names_query_and_remedy() {
    let status = crate::health::types::StuckQueryStatus {
        query_id: "b66b8ffa-755d-45b1-82f6-616f198903bf".to_string(),
        user: "default".to_string(),
        elapsed_secs: 33116.0,
        query_snippet: "WITH stage_0 AS (SELECT ...) SELECT count() FROM stage_2".to_string(),
    };

    let n = HealthScheduler::stuck_query_notification(&status);
    assert_eq!(n.title, "Unkillable ClickHouse query detected");
    let msg = n.message.expect("stuck-query notification must carry a message");
    assert!(
        msg.contains("b66b8ffa-755d-45b1-82f6-616f198903bf"),
        "message must name the query id, got: {msg}"
    );
    assert!(
        msg.contains("9.2 hours"),
        "elapsed must render in hours past 3600s, got: {msg}"
    );
    assert!(
        msg.contains("restarting the ClickHouse server"),
        "message must state the only remedy, got: {msg}"
    );
    assert_eq!(
        n.metadata["query_snippet"],
        "WITH stage_0 AS (SELECT ...) SELECT count() FROM stage_2"
    );

    let event = HealthScheduler::stuck_query_health_event(&status);
    assert_eq!(event.dedup_key, "query:b66b8ffa-755d-45b1-82f6-616f198903bf:stuck");
    assert_eq!(event.category, crate::system_health::HealthCategory::Query);
    assert_eq!(event.resource_type, "clickhouse_query");
}

#[test]
fn ai_provider_failure_and_recovery_share_stable_health_lifecycle() {
    let status = crate::health::types::AiProviderStatus {
        provider_id: Uuid::now_v7(),
        provider_name: "OpenAI".to_string(),
        provider_type: "openai".to_string(),
        is_healthy: false,
        error_message: Some("authentication failed".to_string()),
        checked_at: chrono::Utc::now(),
    };

    let event = HealthScheduler::ai_provider_health_event(&status);
    let recovery_key = HealthScheduler::ai_provider_dedup_key(&status.provider_type);
    assert_eq!(event.dedup_key, recovery_key);
    assert_eq!(event.dedup_key, "service:ai_provider:openai:unavailable");
    assert_eq!(event.resource_type, "ai_provider");
}

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

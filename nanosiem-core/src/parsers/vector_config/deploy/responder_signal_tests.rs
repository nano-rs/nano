// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5387: on open-core Compose the reload signal goes through the Vector
//! container's responder (the api image has no docker CLI), chosen by the
//! responder's heartbeat on the shared validation volume.

use super::*;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

#[tokio::test]
async fn a_recent_heartbeat_is_fresh() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".responder"), "1700000000\n").unwrap();
    assert!(responder_heartbeat_fresh(dir.path(), at(1_700_000_000)).await);
    assert!(responder_heartbeat_fresh(dir.path(), at(1_700_000_030)).await);
    assert!(
        responder_heartbeat_fresh(dir.path(), at(1_700_000_000 + RESPONDER_HEARTBEAT_MAX_AGE.as_secs())).await
    );
    // Clock granularity: a beat a second "ahead" of now is still fresh.
    assert!(responder_heartbeat_fresh(dir.path(), at(1_699_999_999)).await);
}

#[tokio::test]
async fn a_stale_missing_or_garbled_heartbeat_is_not_fresh() {
    let dir = tempfile::tempdir().unwrap();
    assert!(!responder_heartbeat_fresh(dir.path(), at(1_700_000_000)).await, "missing");
    std::fs::write(dir.path().join(".responder"), "1700000000").unwrap();
    assert!(
        !responder_heartbeat_fresh(dir.path(), at(1_700_000_001 + RESPONDER_HEARTBEAT_MAX_AGE.as_secs())).await,
        "stale"
    );
    std::fs::write(dir.path().join(".responder"), "not-a-time").unwrap();
    assert!(!responder_heartbeat_fresh(dir.path(), at(1_700_000_000)).await, "garbled");
}

/// The responder answers the request (as the entrypoint loop does): the
/// reload is delivered without any docker CLI.
#[tokio::test]
async fn a_live_responder_delivers_the_reload() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let reload = root.join("reload");
    std::fs::create_dir_all(&reload).unwrap();
    let responder = tokio::spawn(async move {
        for _ in 0..100 {
            if let Ok(entries) = std::fs::read_dir(&reload) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|e| e == "request") {
                        std::fs::rename(&path, path.with_extension("done")).unwrap();
                        return;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
    let method = request_reload_in(&root, Duration::from_secs(3)).await.unwrap();
    responder.await.unwrap();
    assert_eq!(method, "validation-volume reload request");
}

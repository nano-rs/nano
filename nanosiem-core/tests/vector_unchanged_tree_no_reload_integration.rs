// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5611: a render that leaves the Vector tree as Vector runs it (every
//! nano-api restart without a config change) rewrites no file and sends no
//! reload; a render that changes it writes and reloads as before.
//!
//! Vector is faked: its metrics report the activation marker on disk as
//! running, and a responder on the validation volume answers reload requests
//! (counting them), as the Vector entrypoint's does. No database is needed.
//!
//! `cargo test -p nanosiem-core --test vector_unchanged_tree_no_reload_integration`

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use nanosiem_core::parsers::VectorConfigManager;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

struct FakeVectorMetrics {
    marker_file: PathBuf,
}

impl Respond for FakeVectorMetrics {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let mut body = String::from("nanosiem_vector_reloaded_total{host=\"h\"} 1\n");
        if let Ok(toml) = std::fs::read_to_string(&self.marker_file) {
            if let Some(id) = toml
                .lines()
                .find_map(|l| l.strip_prefix("[sources.").and_then(|r| r.strip_suffix(']')))
            {
                body.push_str(&format!(
                    "nanosiem_vector_component_sent_events_total{{component_id=\"{id}\",host=\"h\"}} 3\n"
                ));
            }
        }
        ResponseTemplate::new(200).set_body_string(body)
    }
}

/// Answers every `<id>.request` with `<id>.done` and counts them.
fn spawn_responder(validation: PathBuf, count: Arc<AtomicU32>) {
    tokio::spawn(async move {
        let dir = validation.join("reload");
        loop {
            let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
            let _ = std::fs::write(validation.join(".responder"), format!("{now}\n"));
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if let Some(id) = name.strip_suffix(".request") {
                        let done = dir.join(format!("{id}.done"));
                        if !done.exists() {
                            count.fetch_add(1, Ordering::SeqCst);
                            let _ = std::fs::write(done, "");
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
}

/// Every entry under `dir` (recursive, dotfiles included) with its mtime: the
/// whole volume Vector watches (`--config-dir /etc/vector --watch-config`).
fn mtimes(dir: &Path) -> Vec<(PathBuf, SystemTime)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let meta = e.metadata().unwrap();
            out.push((e.path(), meta.modified().unwrap()));
            if meta.is_dir() {
                stack.push(e.path());
            }
        }
    }
    out.sort();
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unchanged_render_sends_no_reload_and_a_changed_one_does() {
    let config_dir = tempfile::tempdir().unwrap();
    let validation = tempfile::tempdir().unwrap();
    let marker_file = config_dir.path().join("sources/configs/_nano_activation.toml");
    let metrics = MockServer::start().await;
    Mock::given(wiremock::matchers::method("GET"))
        .respond_with(FakeVectorMetrics { marker_file: marker_file.clone() })
        .mount(&metrics)
        .await;
    // SAFETY: the only test in this binary; set before anything reads them.
    unsafe {
        std::env::set_var("VECTOR_VALIDATION_DIR", validation.path());
        std::env::set_var("VECTOR_CONTAINER_NAME", format!("nan5611-absent-{}", uuid::Uuid::new_v4().simple()));
        std::env::set_var("VECTOR_METRICS_URL", format!("{}/metrics", metrics.uri()));
        std::env::set_var("VECTOR_RELOAD_ACK_TIMEOUT_SECS", "3");
        std::env::remove_var("NANO_PIPELINE_IDENTITY");
    }
    let reloads = Arc::new(AtomicU32::new(0));
    spawn_responder(validation.path().to_path_buf(), reloads.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let manager = VectorConfigManager::new(config_dir.path());

    // First render: the tree is new, Vector is told.
    manager.deploy_and_reload(&[]).await.expect("first deploy");
    assert_eq!(reloads.load(Ordering::SeqCst), 1, "a changed tree reloads");
    let marker = std::fs::read_to_string(&marker_file).unwrap();
    assert!(marker.starts_with("# nano-env-escaped: v1\n"), "{marker}");
    assert!(marker.contains("# nano-tree: "), "{marker}");

    // Second render of the same inputs (an api restart): nothing written, no reload.
    let parsers = config_dir.path().join("sources/parsers");
    // The whole dynamic volume, backup and lock file included.
    let before = mtimes(config_dir.path());
    let marker_before = std::fs::read_to_string(&marker_file).unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    manager.deploy_and_reload(&[]).await.expect("unchanged deploy");
    assert_eq!(reloads.load(Ordering::SeqCst), 1, "an unchanged tree sends no reload");
    assert_eq!(mtimes(config_dir.path()), before, "nothing under the watched tree written (backup included)");
    assert_eq!(std::fs::read_to_string(&marker_file).unwrap(), marker_before, "the marker is kept");

    // Something changed on disk since Vector loaded it: written back and reloaded.
    std::fs::write(parsers.join("_combiner.toml"), "# drifted\n").unwrap();
    manager.deploy_and_reload(&[]).await.expect("changed deploy");
    assert_eq!(reloads.load(Ordering::SeqCst), 2, "a changed tree reloads");
    assert_ne!(std::fs::read_to_string(&marker_file).unwrap(), marker_before, "a new marker");
}

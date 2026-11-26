// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5564: pipeline identity gate and the controlled restart for a sink
//! buffer change (see `pipeline_gate.rs`).

use super::pipeline_gate::*;
use super::VectorConfigManager;
use std::time::Duration;
use tempfile::TempDir;

/// The 0.1.702 `clickhouse_logs` sink as it sat in the volume on the
/// NAN-5553 rehearsal box: disk, drop_newest, acks off.
const LEGACY_0_1_702_PIPELINE: &str = r#"
[sinks.clickhouse_logs]
type = "clickhouse"
inputs = ["clickhouse_mapping"]
endpoint = "${CLICKHOUSE_URL}"

# NAN-2253: disk buffer.
[sinks.clickhouse_logs.buffer]
type = "disk"
max_size = 2147483648
when_full = "drop_newest"

[sinks.clickhouse_logs.acknowledgements]
enabled = false

[sinks.clickhouse_logs.batch]
max_bytes = ${VECTOR_BATCH_MAX_BYTES:-52428800}
"#;

#[test]
fn buffer_sections_read_nanos_interpolating_files() {
    let sections = buffer_sections(LEGACY_0_1_702_PIPELINE);
    assert_eq!(sections.len(), 1);
    assert_eq!(
        sections["clickhouse_logs"],
        "max_size = 2147483648\ntype = \"disk\"\nwhen_full = \"drop_newest\""
    );
    // The committed pipeline (quoted "${VAR:-n}" values, NAN-5810).
    let committed = buffer_sections(&VectorConfigManager::full_pipeline_config_content());
    assert!(committed["clickhouse_logs"].contains("type = \"disk\""), "{committed:?}");
    assert!(committed["clickhouse_logs"].contains("when_full = \"block\""), "{committed:?}");
    assert!(committed.contains_key("clickhouse_parser_health"), "{committed:?}");
    // Nested sections of a sink are not its buffer; every sink is listed.
    assert!(!committed.keys().any(|id| id.contains('.')));
    assert!(!committed["clickhouse_logs"].contains("acknowledgements"));
}

#[test]
fn a_0_1_x_tree_differs_from_the_current_render_in_a_disk_buffer() {
    let live = buffer_sections(LEGACY_0_1_702_PIPELINE);
    let next = buffer_sections(&VectorConfigManager::full_pipeline_config_content());
    assert_eq!(changed_disk_buffers(&live, &next), vec!["clickhouse_logs".to_string()]);
}

#[test]
fn identical_added_removed_and_memory_only_changes_reload_in_place() {
    let disk = buffer_sections("[sinks.a.buffer]\ntype = \"disk\"\nmax_size = 1\n");
    let disk_reformatted =
        buffer_sections("[sinks.a.buffer]\n# a comment\ntype   =   \"disk\"\n\nmax_size = 1\n[sinks.a.batch]\nx = 1\n");
    assert!(changed_disk_buffers(&disk, &disk_reformatted).is_empty());
    let other = buffer_sections("[sinks.b.buffer]\ntype = \"disk\"\nmax_size = 2\n");
    assert!(changed_disk_buffers(&disk, &other).is_empty(), "only added / removed sinks");
    // NAN-5564 review: a disk buffer replaced by the default memory buffer
    // still has to release its lock first.
    let no_buffer = buffer_sections("[sinks.a]\ntype = \"clickhouse\"\n");
    assert_eq!(no_buffer["a"], "");
    assert_eq!(changed_disk_buffers(&disk, &no_buffer), vec!["a".to_string()]);
    let memory_a = buffer_sections("[sinks.a.buffer]\ntype = \"memory\"\nmax_events = 1\n");
    let memory_b = buffer_sections("[sinks.a.buffer]\ntype = \"memory\"\nmax_events = 2\n");
    assert!(changed_disk_buffers(&memory_a, &memory_b).is_empty());
    // memory -> disk (or back) on the same sink is a disk-buffer change.
    assert_eq!(changed_disk_buffers(&memory_a, &disk), vec!["a".to_string()]);
}

#[test]
fn every_toml_spelling_of_a_buffer_is_read_the_same() {
    // NAN-5564 review: the comparison must not assume nano's table form.
    let table = buffer_sections("[sinks.a]\ntype = \"x\"\n\n[sinks.a.buffer]\ntype = \"disk\"\nmax_size = 5\n");
    let dotted = buffer_sections("[sinks.a]\ntype = \"x\"\nbuffer.type = \"disk\"\nbuffer.max_size = 5\n");
    assert_eq!(table["a"], dotted["a"]);
    assert!(changed_disk_buffers(&table, &dotted).is_empty());
    let inline = buffer_sections("[sinks.a]\nbuffer = { type = \"disk\", max_size = 6 }\n");
    assert_eq!(changed_disk_buffers(&table, &inline), vec!["a".to_string()]);
    // Every generated sink's buffer is written in the table form.
    let pipeline = VectorConfigManager::full_pipeline_config_content();
    assert!(!pipeline.lines().any(|l| l.trim_start().starts_with("buffer.") || l.trim_start().starts_with("buffer =")));
}

#[test]
fn an_ack_durability_change_is_a_disk_buffer_change() {
    // NAN-5287 renders the mode inside every blocking disk buffer section.
    let base = VectorConfigManager::pipeline_config_content();
    let fsync = buffer_sections(&super::deploy::with_ack_durability(base, "fsync"));
    let page_cache = buffer_sections(&super::deploy::with_ack_durability(base, "page_cache"));
    let changed = changed_disk_buffers(&fsync, &page_cache);
    assert!(changed.contains(&"clickhouse_logs".to_string()), "{changed:?}");
}

#[test]
fn identity_comes_from_one_clean_line() {
    assert_eq!(pipeline_identity_from(Some(" 2.0.32/fsync/off \n")), Some("2.0.32/fsync/off".into()));
    assert_eq!(pipeline_identity_from(Some("")), None);
    assert_eq!(pipeline_identity_from(Some("   ")), None);
    assert_eq!(pipeline_identity_from(Some("a\nb")), None);
    assert_eq!(pipeline_identity_from(None), None);
}

#[tokio::test]
async fn identity_is_recorded_once_and_can_be_cleared() {
    let tmp = TempDir::new().unwrap();
    assert_eq!(recorded_identity(tmp.path()).await, None);
    assert!(record_identity(tmp.path(), "2.0.32/fsync/off").await.unwrap());
    assert!(!record_identity(tmp.path(), "2.0.32/fsync/off").await.unwrap());
    // Exactly what the entrypoint compares: the first line.
    let text = std::fs::read_to_string(tmp.path().join(PIPELINE_IDENTITY_FILE)).unwrap();
    assert_eq!(text, "2.0.32/fsync/off\n");
    assert!(record_identity(tmp.path(), "2.0.33/fsync/off").await.unwrap());
    assert_eq!(recorded_identity(tmp.path()).await.as_deref(), Some("2.0.33/fsync/off"));
    clear_identity(tmp.path()).await;
    assert_eq!(recorded_identity(tmp.path()).await, None);
}

#[tokio::test]
async fn the_hold_is_removed_when_dropped() {
    let tmp = TempDir::new().unwrap();
    let hold = VectorHold::place(tmp.path()).await.unwrap();
    let path = tmp.path().join(HOLD_FILE);
    let epoch: u64 = std::fs::read_to_string(&path).unwrap().trim().parse().unwrap();
    assert!(epoch > 1_700_000_000);
    drop(hold);
    assert!(!path.exists());
}

/// Answers the first stop request the way the entrypoint's responder does.
async fn responder(root: std::path::PathBuf, verdict: &'static str) {
    let dir = root.join("reload");
    for _ in 0..100 {
        if let Ok(mut entries) = tokio::fs::read_dir(&dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Some(id) = name.strip_suffix(".stop") {
                    let _ = tokio::fs::rename(entry.path(), dir.join(format!("{id}.{verdict}"))).await;
                    return;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn a_stop_request_is_answered_and_cleaned_up() {
    let tmp = TempDir::new().unwrap();
    let answer = tokio::spawn(responder(tmp.path().to_path_buf(), "stopping"));
    request_stop_in(tmp.path(), Duration::from_secs(5)).await.unwrap();
    answer.await.unwrap();
    let left: Vec<_> = std::fs::read_dir(tmp.path().join("reload")).unwrap().collect();
    assert!(left.is_empty(), "{left:?}");
}

#[tokio::test]
async fn a_refused_or_unanswered_stop_request_is_an_error() {
    let tmp = TempDir::new().unwrap();
    let answer = tokio::spawn(responder(tmp.path().to_path_buf(), "refused"));
    let error = request_stop_in(tmp.path(), Duration::from_secs(5)).await.unwrap_err();
    answer.await.unwrap();
    assert!(error.contains("refused"), "{error}");
    // A responder from before NAN-5564 never answers.
    let error = request_stop_in(tmp.path(), Duration::from_millis(300)).await.unwrap_err();
    assert!(error.contains("no responder"), "{error}");
    let left: Vec<_> = std::fs::read_dir(tmp.path().join("reload")).unwrap().collect();
    assert!(left.is_empty(), "{left:?}");
}

#[tokio::test]
async fn a_legacy_tree_in_the_volume_is_a_buffer_change_for_the_current_render() {
    let tmp = TempDir::new().unwrap();
    let manager = VectorConfigManager::new(tmp.path());
    let parsers = tmp.path().join("sources").join("parsers");
    std::fs::create_dir_all(&parsers).unwrap();
    std::fs::write(parsers.join("_pipeline.toml"), LEGACY_0_1_702_PIPELINE).unwrap();
    let changed = manager.candidate_buffer_changes(&[]).await.unwrap();
    assert_eq!(changed, vec!["clickhouse_logs".to_string()]);
    // The comparison renders into a scratch tree: the live file is untouched.
    assert_eq!(std::fs::read_to_string(parsers.join("_pipeline.toml")).unwrap(), LEGACY_0_1_702_PIPELINE);

    // Once the live tree is the current render, nothing changes.
    manager.deploy_parsers(&[]).await.unwrap();
    assert!(manager.candidate_buffer_changes(&[]).await.unwrap().is_empty());
}

#[tokio::test]
async fn the_tree_is_written_and_recorded_before_the_hold_goes() {
    let tmp = TempDir::new().unwrap();
    let validation = TempDir::new().unwrap();
    let manager = VectorConfigManager::new(tmp.path());
    let hold = VectorHold::place(validation.path()).await.unwrap();
    let recorded = manager
        .write_tree_under_hold(&[], None, Some(hold), Some("2.0.32/fsync/off".to_string()))
        .await
        .unwrap();
    assert!(recorded);
    assert!(tmp.path().join("sources/parsers/_pipeline.toml").exists());
    assert_eq!(recorded_identity(tmp.path()).await.as_deref(), Some("2.0.32/fsync/off"));
    assert!(!validation.path().join(HOLD_FILE).exists());
    // Same identity again: nothing new to record.
    assert!(!manager.write_tree_under_hold(&[], None, None, Some("2.0.32/fsync/off".to_string())).await.unwrap());
}

#[tokio::test]
async fn a_failed_write_releases_the_hold_and_records_nothing() {
    let tmp = TempDir::new().unwrap();
    let validation = TempDir::new().unwrap();
    // A config dir that is a regular file: the tree cannot be written.
    let not_a_dir = tmp.path().join("file");
    std::fs::write(&not_a_dir, "x").unwrap();
    let manager = VectorConfigManager::new(&not_a_dir);
    let hold = VectorHold::place(validation.path()).await.unwrap();
    let error = manager
        .write_tree_under_hold(&[], None, Some(hold), Some("2.0.32/fsync/off".to_string()))
        .await;
    assert!(error.is_err());
    assert!(!validation.path().join(HOLD_FILE).exists());
    assert_eq!(recorded_identity(tmp.path()).await, None);
}

// ---- NAN-5564 release review ------------------------------------------------

fn log_parser(name: &str, matches: &[&str]) -> crate::parsers::types::Parser {
    let mut bytes = [0u8; 16];
    for (i, b) in name.bytes().enumerate() {
        bytes[i % 16] = bytes[i % 16].wrapping_mul(31).wrapping_add(b);
    }
    let at = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    crate::parsers::types::Parser {
        activation_parked: false,
        id: uuid::Uuid::from_bytes(bytes),
        name: name.to_string(),
        description: None,
        source_type: "http".to_string(),
        parser_vrl: format!(".vendor = \"{name}\""),
        output_fields: None,
        feed_id: None,
        dispatch_source_config_id: None,
        dispatch_route_name: None,
        enabled: true,
        validated: true,
        validation_error: None,
        category: None,
        vendor: None,
        product: None,
        kind: "log".to_string(),
        enrich_kind: None,
        enrich_source: None,
        target_table: None,
        normalize_vrl: None,
        namespace: "default".to_string(),
        timezone: "UTC".to_string(),
        match_values: Some(matches.iter().map(|m| m.to_string()).collect()),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        extension_vrl: None,
        extension_enabled: false,
        created_at: at,
        updated_at: at,
    }
}

#[tokio::test]
async fn one_broken_parser_never_keeps_the_tree_from_being_written() {
    // P2-2: two parsers claiming one source_type make the strict render refuse
    // the whole tree (and so the gate would stay shut). The boot fallback
    // renders everything else and records the identity.
    let tmp = TempDir::new().unwrap();
    let manager = VectorConfigManager::new(tmp.path());
    let parsers = vec![
        log_parser("good_one", &["good_one"]),
        log_parser("twin_a", &["shared_type"]),
        log_parser("twin_b", &["shared_type"]),
    ];
    assert!(manager.deploy_parsers(&parsers).await.is_err(), "the strict render refuses a claim collision");
    let (kept, skipped) = manager.renderable_subset(&parsers);
    assert_eq!(skipped, vec!["twin_a".to_string(), "twin_b".to_string()]);
    assert_eq!(kept.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), vec!["good_one"]);
    let recorded = manager
        .write_tree_under_hold(&kept, None, None, Some("2.0.32/fsync/off".to_string()))
        .await
        .unwrap();
    assert!(recorded);
    assert!(tmp.path().join("sources/parsers/good_one.toml").exists());
    assert!(!tmp.path().join("sources/parsers/twin_a.toml").exists());
    assert_eq!(recorded_identity(tmp.path()).await.as_deref(), Some("2.0.32/fsync/off"));
}

#[tokio::test]
async fn an_orphaned_fetch_binding_is_left_out_of_the_render() {
    // P2-2: the strict resolve refuses an orphaned fetch binding (the whole
    // boot render then fails). The boot fallback resolves leniently: the
    // orphan keeps no route, the renderer leaves it out, the rest is written.
    let mut orphan = log_parser("orphan_feed", &["orphan_feed"]);
    orphan.source_type = "kafka".to_string();
    orphan.dispatch_source_config_id = Some(uuid::Uuid::from_u128(7));
    let mut parsers = vec![log_parser("good_one", &["good_one"]), orphan];
    let strict = crate::parsers::repository::apply_resolved_dispatch_routes(
        &mut parsers, &std::collections::HashMap::new(),
    );
    assert!(strict.is_err(), "the strict resolve refuses the orphan");
    assert!(parsers[1].dispatch_route_name.is_none());
    let tmp = TempDir::new().unwrap();
    let manager = VectorConfigManager::new(tmp.path());
    manager.deploy_parsers(&parsers).await.unwrap();
    assert!(tmp.path().join("sources/parsers/good_one.toml").exists());
    assert!(!tmp.path().join("sources/parsers/orphan_feed.toml").exists());
}

#[tokio::test]
async fn an_unbound_fetch_draft_is_left_out_and_every_other_source_renders() {
    // NAN-5789: a kafka draft saved with no source configuration used to fail
    // the whole render. Resolved, it keeps no route; the render leaves only it
    // out and writes every other source.
    let mut draft = log_parser("kafka_draft", &["kafka_draft"]);
    draft.source_type = "kafka".to_string();
    draft.dispatch_source_config_id = None;
    let mut parsers = vec![log_parser("good_one", &["good_one"]), draft, log_parser("good_two", &["good_two"])];
    let _ = crate::parsers::repository::apply_resolved_dispatch_routes(
        &mut parsers, &std::collections::HashMap::new(),
    );
    let unroutable = crate::parsers::unrouted::classify(&parsers, None);
    assert_eq!(unroutable.len(), 1);
    assert_eq!(unroutable[0].name, "kafka_draft");
    let tmp = TempDir::new().unwrap();
    let manager = VectorConfigManager::new(tmp.path());
    manager.deploy_parsers(&parsers).await.unwrap();
    assert!(tmp.path().join("sources/parsers/good_one.toml").exists());
    assert!(tmp.path().join("sources/parsers/good_two.toml").exists());
    assert!(!tmp.path().join("sources/parsers/kafka_draft.toml").exists());
    let combiner = std::fs::read_to_string(tmp.path().join("sources/parsers/_combiner.toml")).unwrap_or_default();
    assert!(!combiner.contains("kafka_draft"), "the draft must not be wired anywhere: {combiner}");
}

#[tokio::test]
async fn the_boot_render_rewrites_a_marker_left_by_a_rollback() {
    // A rollback's older api never touches the marker; the re-upgraded api's
    // boot render makes it say exactly this identity. NAN-5611: a marker that
    // already says exactly that is left alone (no write on every api start).
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join(PIPELINE_IDENTITY_FILE);
    std::fs::write(&file, "2.0.32/fsync/off\n").unwrap();
    let before = std::fs::metadata(&file).unwrap().modified().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    assert!(!rewrite_identity(tmp.path(), "2.0.32/fsync/off").await.unwrap());
    assert_eq!(std::fs::metadata(&file).unwrap().modified().unwrap(), before);
    // Same first line, other content: rewritten to exactly the identity.
    std::fs::write(&file, "2.0.32/fsync/off\nleft by 2.0.31\n").unwrap();
    assert!(rewrite_identity(tmp.path(), "2.0.32/fsync/off").await.unwrap());
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "2.0.32/fsync/off\n");
    // Absent (cleared by the rollback): written.
    clear_identity(tmp.path()).await;
    assert!(rewrite_identity(tmp.path(), "2.0.33/fsync/off").await.unwrap());
    assert_eq!(recorded_identity(tmp.path()).await.as_deref(), Some("2.0.33/fsync/off"));
    // No temp file is left behind.
    let leftovers: Vec<_> = std::fs::read_dir(tmp.path()).unwrap().flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

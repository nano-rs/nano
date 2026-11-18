// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5564: no acknowledged event may be lost across an upgrade or a change
//! to a sink's buffer settings.
//!
//! Two mechanisms, both shared with `config/vector/.nano/vector-entrypoint.sh`:
//!
//! * **Pipeline identity.** Compose gives nano-api and Vector the same
//!   `NANO_PIPELINE_IDENTITY` (release / ack durability / fan-in slots). After
//!   a deploy has written the dynamic tree, the api records the identity it
//!   rendered for in `<config dir>/.nano-pipeline-identity`. The entrypoint
//!   does not start Vector (so its ports refuse connections and nothing is
//!   acknowledged) until that file names its own identity. A Vector created
//!   for a new release therefore never runs the tree the previous release
//!   rendered (a 0.1.x tree acknowledges before durability).
//! * **Controlled restart.** Vector cannot hot-reload a sink whose disk buffer
//!   settings change: the old topology still holds the buffer's lock, the
//!   reload fails, the restore fails and Vector exits with events in flight.
//!   When a deploy would change a disk-buffered sink that is running, the api
//!   holds the next start (`<validation dir>/.nano-vector-hold`), asks the
//!   entrypoint's responder to stop Vector gracefully (SIGTERM: sources close,
//!   in-flight events reach the disk buffers), waits for it to go down, writes
//!   the tree, then releases the hold. The restart policy starts Vector on the
//!   new tree.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Compose sets this on nano-api and Vector from the same `.env` values.
pub const PIPELINE_IDENTITY_ENV: &str = "NANO_PIPELINE_IDENTITY";
/// In the api's config dir (Vector's `/etc/vector/dynamic`).
pub(super) const PIPELINE_IDENTITY_FILE: &str = ".nano-pipeline-identity";
/// In the validation volume (outside Vector's watched config dirs).
pub(super) const HOLD_FILE: &str = ".nano-vector-hold";
/// The responder answers within a second; this also covers a busy host.
pub(super) const STOP_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Vector's compose stop_grace_period is 60 s.
pub(super) const STOP_WAIT: Duration = Duration::from_secs(90);

/// The identity this api renders for, when compose set one.
pub(super) fn pipeline_identity() -> Option<String> {
    pipeline_identity_from(std::env::var(PIPELINE_IDENTITY_ENV).ok().as_deref())
}

pub(super) fn pipeline_identity_from(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    // One line: the entrypoint compares the file's first line.
    (!value.is_empty() && !value.contains(['\n', '\r'])).then(|| value.to_string())
}

/// The identity the tree at `config_dir` was rendered for, if recorded.
pub(super) async fn recorded_identity(config_dir: &Path) -> Option<String> {
    let text = tokio::fs::read_to_string(config_dir.join(PIPELINE_IDENTITY_FILE))
        .await
        .ok()?;
    text.lines().next().map(|line| line.trim().to_string())
}

/// Record `identity` for the tree at `config_dir` (atomic). `Ok(true)` when
/// the file changed, `Ok(false)` when it already named `identity`.
pub(super) async fn record_identity(config_dir: &Path, identity: &str) -> std::io::Result<bool> {
    if recorded_identity(config_dir).await.as_deref() == Some(identity) {
        return Ok(false);
    }
    let tmp = config_dir.join(format!("{PIPELINE_IDENTITY_FILE}.tmp"));
    tokio::fs::write(&tmp, format!("{identity}\n")).await?;
    tokio::fs::rename(&tmp, config_dir.join(PIPELINE_IDENTITY_FILE)).await?;
    Ok(true)
}

/// Rewrite the identity even when it already names `identity` (the api's
/// boot render: a marker an older release left behind after a rollback must
/// never stand for a tree this api did not just write).
pub(super) async fn rewrite_identity(config_dir: &Path, identity: &str) -> std::io::Result<()> {
    let tmp = config_dir.join(format!("{PIPELINE_IDENTITY_FILE}.tmp"));
    tokio::fs::write(&tmp, format!("{identity}\n")).await?;
    tokio::fs::rename(&tmp, config_dir.join(PIPELINE_IDENTITY_FILE)).await
}

/// Forget the identity (the tree was rolled back to another identity's).
pub(super) async fn clear_identity(config_dir: &Path) {
    let _ = tokio::fs::remove_file(config_dir.join(PIPELINE_IDENTITY_FILE)).await;
}

/// The buffer settings of every sink in `content`, normalized (comments and
/// blank lines dropped, whitespace collapsed): `[sinks.<id>.buffer]` sections,
/// `buffer.<key> = ...` dotted keys and `buffer = { ... }` inline tables inside
/// `[sinks.<id>]`. A sink with none maps to "" (Vector's default memory
/// buffer), so a disk buffer that goes away is still a change. Text-based on
/// purpose: nano's interpolating files hold unquoted `${VAR:-n}` values that
/// are not TOML.
pub(super) fn buffer_sections(content: &str) -> BTreeMap<String, String> {
    fn norm(line: &str) -> String {
        line.split_whitespace().collect::<Vec<_>>().join(" ")
    }
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    // (sink id, inside its `.buffer` sub-table?)
    let mut current: Option<(String, bool)> = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') {
            current = trimmed
                .strip_prefix("[sinks.")
                .and_then(|rest| rest.strip_suffix(']'))
                .and_then(|path| {
                    let mut parts = path.splitn(2, '.');
                    let id = parts.next()?.to_string();
                    if id.is_empty() || id.contains(['[', ']']) {
                        return None;
                    }
                    match parts.next() {
                        None => Some((id, false)),
                        Some("buffer") => Some((id, true)),
                        Some(_) => None,
                    }
                });
            if let Some((id, _)) = &current {
                out.entry(id.clone()).or_default();
            }
            continue;
        }
        let Some((id, in_buffer)) = &current else { continue };
        let entry = out.entry(id.clone()).or_default();
        if *in_buffer {
            entry.push(norm(trimmed));
        } else if let Some(rest) = trimmed.strip_prefix("buffer.") {
            entry.push(norm(rest));
        } else if trimmed.starts_with("buffer ") || trimmed.starts_with("buffer=") {
            entry.push(norm(trimmed));
        }
    }
    out.into_iter()
        .map(|(id, mut lines)| {
            lines.sort();
            (id, lines.join("\n"))
        })
        .collect()
}

fn is_disk(section: &str) -> bool {
    let compact = section.replace(' ', "");
    compact.lines().any(|line| line.starts_with("type=\"disk\""))
        || compact.contains("type=\"disk\"")
}

/// Sinks present in both trees whose buffer settings differ while either side
/// is a disk buffer (including a disk buffer replaced by the default memory
/// one): the reloads Vector cannot apply in place. A sink that is only added
/// or only removed is not one (no lock is contended).
pub(super) fn changed_disk_buffers(
    live: &BTreeMap<String, String>,
    candidate: &BTreeMap<String, String>,
) -> Vec<String> {
    live.iter()
        .filter_map(|(id, old)| {
            let new = candidate.get(id)?;
            (old != new && (is_disk(old) || is_disk(new))).then(|| id.clone())
        })
        .collect()
}

/// The buffer sections of every `*.toml` directly in `dir`.
pub(super) async fn buffer_sections_in(dir: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return out;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        if let Ok(text) = tokio::fs::read_to_string(&path).await {
            out.extend(buffer_sections(&text));
        }
    }
    out
}

/// Holds Vector's next start while it exists; removed on drop.
#[derive(Debug)]
pub(super) struct VectorHold {
    path: PathBuf,
}

impl VectorHold {
    pub(super) async fn place(validation_root: &Path) -> std::io::Result<Self> {
        let path = validation_root.join(HOLD_FILE);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let tmp = validation_root.join(format!("{HOLD_FILE}.tmp"));
        tokio::fs::write(&tmp, format!("{now}\n")).await?;
        tokio::fs::rename(&tmp, &path).await?;
        Ok(Self { path })
    }
}

impl Drop for VectorHold {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Ask the entrypoint's responder to stop Vector (SIGTERM to PID 1 after
/// checking it is the Vector binary). `Err` when nothing answered (a responder
/// from before NAN-5564 ignores the request) or it refused.
pub(super) async fn request_stop_in(root: &Path, timeout: Duration) -> Result<(), String> {
    let dir = root.join("reload");
    let id = uuid::Uuid::new_v4().simple().to_string();
    let io = |e: std::io::Error| format!("could not write a stop request to {}: {e}", dir.display());
    tokio::fs::create_dir_all(&dir).await.map_err(io)?;
    let tmp = dir.join(format!(".{id}.tmp"));
    tokio::fs::write(&tmp, b"TERM\n").await.map_err(io)?;
    tokio::fs::rename(&tmp, dir.join(format!("{id}.stop")))
        .await
        .map_err(io)?;
    let deadline = tokio::time::Instant::now() + timeout;
    let outcome = loop {
        if tokio::fs::try_exists(dir.join(format!("{id}.stopping"))).await.unwrap_or(false) {
            break Ok(());
        }
        if tokio::fs::try_exists(dir.join(format!("{id}.refused"))).await.unwrap_or(false) {
            break Err("the Vector container refused the stop request (PID 1 is not the Vector binary)".to_string());
        }
        if tokio::time::Instant::now() >= deadline {
            break Err("no responder answered the stop request (a Vector container from before NAN-5564)".to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    for suffix in ["stop", "stopping", "refused"] {
        let _ = tokio::fs::remove_file(dir.join(format!("{id}.{suffix}"))).await;
    }
    outcome
}

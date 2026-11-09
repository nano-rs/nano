// SPDX-License-Identifier: AGPL-3.0-or-later

//! `nanosiem-api --vector-tap-relay` (NAN-4919): the only client of Vector's
//! loopback-bound gRPC API.
//!
//! Runs in the Vector container's network namespace (compose
//! `network_mode: service:vector`; a sidecar container in the k8s pod) and
//! serves `POST /v1/tap` to nano-api plus an unauthenticated, non-sensitive
//! `/healthz` readiness verdict for the host-local ingest edge. The readiness
//! verdict requires Vector's own loopback health API, a fresh consumer marker,
//! its acknowledged generation and a valid installed token document.
//!
//! NAN-5134: a host that is installing a NEW generation is still ready. While
//! the consumer waits for Vector's ack, `current` names the candidate (recorded
//! in `.nano-installing`) and Vector keeps serving the acknowledged topology,
//! so the readiness verdict accepts that pointer. Before this, every ingest
//! host reported 503 for the whole install window at the same time.
//!
//! NAN-5133: `GET /v1/generation` (same bearer token as `/v1/tap`) reports this
//! host's installed, installing and last-failed generation so nano-api can
//! grade a role-split deploy by the ingest hosts' own acknowledgement.
//!
//! `POST /v1/tap` uses
//! `Authorization: Bearer $NANO_VECTOR_TAP_TOKEN` and a [`TapRequest`] naming
//! one exact component. It captures at most the requested events for at most
//! 60 s from Vector's sampled tap and returns them. It holds no database
//! credentials, reads no event secrets, and never exposes the Vector API
//! itself. At most [`MAX_CONCURRENT_TAPS`] captures run at once.

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use nanosiem_core::parsers::pipe::tap::{
    self, DEFAULT_RELAY_LISTEN, DEFAULT_VECTOR_API, MIN_TOKEN_BYTES, RELAY_LISTEN_ENV,
    RELAY_TOKEN_ENV, TapCapture, TapRequest, VECTOR_API_ENV,
};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::Semaphore;

/// The argument that turns the API binary into the tap relay.
pub const RELAY_ARGUMENT: &str = "--vector-tap-relay";
pub const MAX_CONCURRENT_TAPS: usize = 4;
const RUNTIME_DIR_ENV: &str = "NANO_VECTOR_RUNTIME_DIR";
const TOKENS_FILE_ENV: &str = "NANO_VECTOR_TOKENS_FILE";
const READY_FILE_ENV: &str = "NANO_VECTOR_READY_FILE";
const READY_MAX_AGE_ENV: &str = "NANO_VECTOR_READY_MAX_AGE_SECS";
const DEFAULT_READY_MAX_AGE_SECS: u64 = 15;

#[derive(Clone)]
struct Readiness {
    runtime_dir: PathBuf,
    tokens_file: PathBuf,
    ready_file: PathBuf,
    max_age: Duration,
}

#[derive(Clone)]
struct Relay {
    token: Arc<str>,
    vector_api: Arc<str>,
    gate: Arc<Semaphore>,
    readiness: Option<Readiness>,
    http: reqwest::Client,
}

async fn handle(
    State(relay): State<Relay>,
    headers: HeaderMap,
    Json(request): Json<TapRequest>,
) -> Result<Json<TapCapture>, (StatusCode, String)> {
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !tap::token_matches(&relay.token, presented) {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized".into()));
    }
    request
        .validate()
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let _permit = relay
        .gate
        .clone()
        .try_acquire_owned()
        .map_err(|_| (StatusCode::TOO_MANY_REQUESTS, "tap capacity is busy".into()))?;
    tap::capture(&relay.vector_api, &request)
        .await
        .map(Json)
        .map_err(|e| (StatusCode::BAD_GATEWAY, e))
}

fn installed_files_are_ready(readiness: &Readiness) -> bool {
    let Ok(marker) = std::fs::read_to_string(&readiness.ready_file) else {
        return false;
    };
    let mut marker = marker.split_whitespace();
    let Some(generation) = marker.next() else {
        return false;
    };
    let Some(written_at) = marker.next().and_then(|value| value.parse::<u64>().ok()) else {
        return false;
    };
    if marker.next().is_some()
        || generation.len() != 20
        || !generation.bytes().all(|byte| byte.is_ascii_digit())
        || generation.bytes().all(|byte| byte == b'0')
    {
        return false;
    }
    let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return false;
    };
    if written_at > now.as_secs().saturating_add(5)
        || now.as_secs().saturating_sub(written_at) > readiness.max_age.as_secs()
    {
        return false;
    }
    let Ok(installed) = std::fs::read_to_string(readiness.runtime_dir.join(".nano-generation"))
    else {
        return false;
    };
    if installed.trim() != generation
        || !readiness
            .runtime_dir
            .join("generations")
            .join(generation)
            .is_dir()
        || !pointer_is_installed_or_installing(&readiness.runtime_dir, generation)
    {
        return false;
    }
    let Ok(tokens) = std::fs::read(&readiness.tokens_file) else {
        return false;
    };
    let Ok(tokens): Result<serde_json::Value, _> = serde_json::from_slice(&tokens) else {
        return false;
    };
    tokens.get("version").and_then(serde_json::Value::as_u64) == Some(1)
        && tokens
            .get("tokens")
            .is_some_and(serde_json::Value::is_array)
}

/// `current` must name the acknowledged generation, or the candidate the
/// consumer is installing right now (NAN-5134). Vector keeps the acknowledged
/// topology running until a reload succeeds, so both mean "accepts events".
fn pointer_is_installed_or_installing(runtime_dir: &std::path::Path, installed: &str) -> bool {
    let Ok(pointer) = std::fs::read_link(runtime_dir.join("current")) else {
        return false;
    };
    if pointer == std::path::Path::new(&format!("generations/{installed}")) {
        return true;
    }
    let Some(installing) = read_generation_file(&runtime_dir.join(".nano-installing")) else {
        return false;
    };
    pointer == std::path::Path::new(&format!("generations/{installing}"))
        && runtime_dir.join("generations").join(&installing).is_dir()
}

/// First whitespace token of a marker file, when it is a positive 20-digit
/// generation directory name.
fn read_generation_file(path: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let token = text.split_whitespace().next()?;
    (token.len() == 20
        && token.bytes().all(|byte| byte.is_ascii_digit())
        && !token.bytes().all(|byte| byte == b'0'))
    .then(|| token.to_string())
}

/// This host's generation state for nano-api's role-split deploy grading.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct GenerationStatus {
    /// Generation Vector acknowledged (0 = bootstrap / none).
    pub installed: u64,
    /// Candidate the consumer is installing right now.
    pub installing: Option<u64>,
    /// Last generation this host refused, saw rejected, or rolled back.
    pub failed: Option<u64>,
    /// Why `failed` failed: `refused`, `rejected` or `unacknowledged`.
    pub failed_reason: Option<String>,
}

fn generation_status(runtime_dir: &std::path::Path) -> GenerationStatus {
    let as_number = |value: Option<String>| value.and_then(|v| v.parse::<u64>().ok());
    let installed = as_number(read_generation_file(&runtime_dir.join(".nano-generation"))).unwrap_or(0);
    let installing = as_number(read_generation_file(&runtime_dir.join(".nano-installing")));
    let failed_text = std::fs::read_to_string(runtime_dir.join(".nano-failed-generation")).unwrap_or_default();
    let mut failed_fields = failed_text.split_whitespace();
    let failed = failed_fields
        .next()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0);
    let failed_reason = failed
        .and(failed_fields.next())
        .filter(|reason| matches!(*reason, "refused" | "rejected" | "unacknowledged"))
        .map(str::to_string);
    GenerationStatus {
        installed,
        installing,
        failed,
        failed_reason,
    }
}

async fn generation(
    State(relay): State<Relay>,
    headers: HeaderMap,
) -> Result<Json<GenerationStatus>, (StatusCode, String)> {
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !tap::token_matches(&relay.token, presented) {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized".into()));
    }
    let Some(readiness) = &relay.readiness else {
        return Err((StatusCode::NOT_FOUND, "no runtime directory".into()));
    };
    Ok(Json(generation_status(&readiness.runtime_dir)))
}

async fn readiness(State(relay): State<Relay>) -> Result<&'static str, StatusCode> {
    let Some(readiness) = &relay.readiness else {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };
    if !installed_files_are_ready(readiness) {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let response = relay
        .http
        .get(format!("{}/health", relay.vector_api.trim_end_matches('/')))
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if !response.status().is_success() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok("ok\n")
}

fn build_router(token: &str, vector_api: &str, readiness_config: Option<Readiness>) -> Router {
    Router::new()
        .route("/v1/tap", post(handle))
        .route("/v1/generation", get(generation))
        .route("/health", get(|| async { "ok" }))
        .route("/healthz", get(readiness))
        .with_state(Relay {
            token: token.into(),
            vector_api: vector_api.into(),
            gate: Arc::new(Semaphore::new(MAX_CONCURRENT_TAPS)),
            readiness: readiness_config,
            http: reqwest::Client::new(),
        })
}

/// Build the relay router (tests drive it directly).
pub fn router(token: &str, vector_api: &str) -> Router {
    build_router(token, vector_api, None)
}

/// Entry point for `nanosiem-api --vector-tap-relay`.
pub fn relay_main() -> anyhow::Result<()> {
    let token = std::env::var(RELAY_TOKEN_ENV).unwrap_or_default();
    if token.len() < MIN_TOKEN_BYTES {
        anyhow::bail!("{RELAY_TOKEN_ENV} must be at least {MIN_TOKEN_BYTES} bytes");
    }
    let listen = std::env::var(RELAY_LISTEN_ENV).unwrap_or_else(|_| DEFAULT_RELAY_LISTEN.into());
    let vector_api = std::env::var(VECTOR_API_ENV).unwrap_or_else(|_| DEFAULT_VECTOR_API.into());
    let runtime_dir = PathBuf::from(
        std::env::var(RUNTIME_DIR_ENV).unwrap_or_else(|_| "/etc/vector/runtime".into()),
    );
    let tokens_file = PathBuf::from(
        std::env::var(TOKENS_FILE_ENV)
            .unwrap_or_else(|_| "/etc/vector/dynamic/ingest-tokens/tokens.json".into()),
    );
    let ready_file = PathBuf::from(std::env::var(READY_FILE_ENV).unwrap_or_else(|_| {
        runtime_dir
            .join(".nano-ready")
            .to_string_lossy()
            .into_owned()
    }));
    let max_age = std::env::var(READY_MAX_AGE_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value >= 5)
        .unwrap_or(DEFAULT_READY_MAX_AGE_SECS);
    let readiness_config = Readiness {
        runtime_dir,
        tokens_file,
        ready_file,
        max_age: Duration::from_secs(max_age),
    };
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(async move {
            let listener = tokio::net::TcpListener::bind(&listen).await?;
            eprintln!("nano vector tap relay listening on {listen} (Vector API {vector_api})");
            axum::serve(
                listener,
                build_router(&token, &vector_api, Some(readiness_config)),
            )
            .await?;
            Ok(())
        })
}

#[cfg(test)]
mod readiness_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn readiness_requires_matching_fresh_generation_and_tokens() {
        let root = std::env::temp_dir().join(format!(
            "nano-vector-readiness-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let runtime = root.join("runtime");
        let dynamic = root.join("dynamic");
        let generation = "00000000000000000042";
        std::fs::create_dir_all(runtime.join("generations").join(generation)).unwrap();
        std::fs::create_dir_all(&dynamic).unwrap();
        std::fs::write(runtime.join(".nano-generation"), format!("{generation}\n")).unwrap();
        symlink(format!("generations/{generation}"), runtime.join("current")).unwrap();
        let tokens = dynamic.join("tokens.json");
        std::fs::write(&tokens, r#"{"version":1,"tokens":[]}"#).unwrap();
        let ready = runtime.join(".nano-ready");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        std::fs::write(&ready, format!("{generation} {now}\n")).unwrap();
        let config = Readiness {
            runtime_dir: runtime,
            tokens_file: tokens,
            ready_file: ready.clone(),
            max_age: Duration::from_secs(15),
        };
        assert!(installed_files_are_ready(&config));
        std::fs::write(&ready, format!("{generation} {}\n", now - 30)).unwrap();
        assert!(!installed_files_are_ready(&config));
        std::fs::remove_dir_all(root).unwrap();
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "nano-vector-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    /// NAN-5134: mid-install the pointer names the candidate while Vector still
    /// serves the acknowledged generation. That host is ready; an unrecorded
    /// pointer move (or one to a missing directory) is not.
    #[test]
    fn readiness_holds_through_an_install_window() {
        let root = scratch("install-window");
        let runtime = root.join("runtime");
        let dynamic = root.join("dynamic");
        let installed = "00000000000000000042";
        let candidate = "00000000000000000043";
        std::fs::create_dir_all(runtime.join("generations").join(installed)).unwrap();
        std::fs::create_dir_all(runtime.join("generations").join(candidate)).unwrap();
        std::fs::create_dir_all(&dynamic).unwrap();
        std::fs::write(runtime.join(".nano-generation"), format!("{installed}\n")).unwrap();
        symlink(format!("generations/{candidate}"), runtime.join("current")).unwrap();
        let tokens = dynamic.join("tokens.json");
        std::fs::write(&tokens, r#"{"version":1,"tokens":[]}"#).unwrap();
        let ready = runtime.join(".nano-ready");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        std::fs::write(&ready, format!("{installed} {now}\n")).unwrap();
        let config = Readiness {
            runtime_dir: runtime.clone(),
            tokens_file: tokens,
            ready_file: ready,
            max_age: Duration::from_secs(15),
        };
        // Pointer moved with no install recorded: not ready (unknown state).
        assert!(!installed_files_are_ready(&config));
        // Install recorded: ready, Vector still serves generation 42.
        std::fs::write(runtime.join(".nano-installing"), format!("{candidate}\n")).unwrap();
        assert!(installed_files_are_ready(&config));
        // Candidate directory gone (rolled back and pruned): not ready.
        std::fs::remove_dir_all(runtime.join("generations").join(candidate)).unwrap();
        assert!(!installed_files_are_ready(&config));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn generation_status_reports_installed_installing_and_failed() {
        let root = scratch("generation-status");
        assert_eq!(
            generation_status(&root),
            GenerationStatus {
                installed: 0,
                installing: None,
                failed: None,
                failed_reason: None
            }
        );
        std::fs::write(root.join(".nano-generation"), "00000000000000000007\n").unwrap();
        std::fs::write(root.join(".nano-installing"), "00000000000000000008\n").unwrap();
        std::fs::write(root.join(".nano-failed-generation"), "8 rejected\n").unwrap();
        assert_eq!(
            generation_status(&root),
            GenerationStatus {
                installed: 7,
                installing: Some(8),
                failed: Some(8),
                failed_reason: Some("rejected".into())
            }
        );
        // The bootstrap marker is "nothing installed", never generation 0 acked.
        std::fs::write(root.join(".nano-generation"), "00000000000000000000\n").unwrap();
        assert_eq!(generation_status(&root).installed, 0);
        std::fs::remove_dir_all(root).unwrap();
    }
}

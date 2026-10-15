// SPDX-License-Identifier: AGPL-3.0-or-later

//! One lean tenant's source publisher. Credentials are supplied as private files.
//!
//! ```text
//! lake_lean_enrichment_coordinator <TENANT_UUID> <LISTEN_ADDR> <R2_CREDENTIAL_FILE> <TOKEN_FILE> <ABSOLUTE_SCRATCH_DIR>
//! ```
//!
//! The R2 credential file (`S3Location` JSON) is re-read every
//! `NANO_LEAN_COORDINATOR_CREDENTIAL_RELOAD_SECONDS` (default 60): a rotated
//! short-lived key (a Secret update) is swapped in without a restart. Its
//! endpoint, bucket and tenant prefix may never change. `GET /healthz` is
//! unauthenticated and returns `{"status":"ok"}`.
//!
//! NAN-3503: when `NANO_LEAN_COORDINATOR_IDENTITY_TOKEN_FILE` names a file,
//! its token is accepted ONLY on the identity-directory write routes a
//! connector runner needs (deltas, staged run rows, run commit, run abort);
//! every other route answers 403 to it. Unset keeps today's behavior. Both
//! tokens must be at least 32 characters and differ. Both token files are
//! re-read on the same interval as the R2 credential: a rotation that still
//! validates is swapped in; anything else keeps the current tokens.

use anyhow::{bail, ensure, Context, Result};
use nanosiem_lake_worker::{
    lean_enrichment_coordinator::{router, CoordinatorAuth, LeanCoordinatorState},
    part_ingest::s3_store::{S3Location, S3ObjectStore},
};
use std::{net::SocketAddr, path::Path, path::PathBuf, sync::Arc, time::Duration};
use uuid::Uuid;

const IDENTITY_TOKEN_ENV: &str = "NANO_LEAN_COORDINATOR_IDENTITY_TOKEN_FILE";

const USAGE: &str = "usage: lake_lean_enrichment_coordinator <TENANT_UUID> <LISTEN_ADDR> <R2_CREDENTIAL_FILE> <TOKEN_FILE> <ABSOLUTE_SCRATCH_DIR>";

fn read_location(path: &Path, tenant: Uuid) -> Result<(S3Location, Vec<u8>)> {
    let bytes = std::fs::read(path).context("tenant R2 credential file")?;
    ensure!(
        bytes.len() <= 16 * 1024,
        "tenant R2 credential file is too large"
    );
    let location: S3Location =
        serde_json::from_slice(&bytes).context("tenant R2 credential file")?;
    let expected = format!("lake/enrichment/v1/tenant_id={tenant}/");
    if location.prefix != expected {
        bail!("coordinator R2 credential prefix differs from process tenant");
    }
    Ok((location, bytes))
}

/// Swap in a rotated credential; the store identity (endpoint, bucket,
/// region, tenant prefix) is pinned to what the process booted with.
async fn reload_credentials(
    store: Arc<S3ObjectStore>,
    path: PathBuf,
    tenant: Uuid,
    boot: S3Location,
    mut last: Vec<u8>,
    every: Duration,
) {
    loop {
        tokio::time::sleep(every).await;
        match read_location(&path, tenant) {
            Ok((next, bytes)) if bytes != last => {
                if (
                    next.endpoint.as_str(),
                    next.bucket.as_str(),
                    next.region.as_str(),
                ) != (
                    boot.endpoint.as_str(),
                    boot.bucket.as_str(),
                    boot.region.as_str(),
                ) {
                    tracing::error!(
                        "rotated R2 credential names another store; keeping the current one"
                    );
                    continue;
                }
                match store.replace(&next) {
                    Ok(()) => {
                        tracing::info!("tenant R2 credential rotated");
                        last = bytes;
                    }
                    Err(error) => {
                        tracing::error!(error = %format!("{error:#}"), "rotated R2 credential refused")
                    }
                }
            }
            Ok(_) => {}
            Err(error) => {
                tracing::error!(error = %format!("{error:#}"), "tenant R2 credential unreadable; keeping the current one")
            }
        }
    }
}

/// Read and validate the token files. Errors never carry token material.
fn read_auth(full: &Path, identity_writer: Option<&Path>) -> Result<CoordinatorAuth> {
    let read = |path: &Path, what: &'static str| -> Result<String> {
        let text =
            std::fs::read_to_string(path).map_err(|_| anyhow::anyhow!("{what} unreadable"))?;
        ensure!(text.len() <= 4096, "{what} is too large");
        Ok(text.trim().to_string())
    };
    let full = read(full, "coordinator token file")?;
    let identity_writer = identity_writer
        .map(|path| read(path, "coordinator identity-writer token file"))
        .transpose()?;
    CoordinatorAuth::from_tokens(&full, identity_writer.as_deref())
}

/// Swap in rotated bearer tokens (full and, when configured, identity-writer).
async fn reload_tokens(
    state: LeanCoordinatorState,
    full: PathBuf,
    identity_writer: Option<PathBuf>,
    every: Duration,
) {
    loop {
        tokio::time::sleep(every).await;
        match read_auth(&full, identity_writer.as_deref()).and_then(|next| state.rotate_auth(next))
        {
            Ok(true) => tracing::info!("coordinator bearer tokens rotated"),
            Ok(false) => {}
            Err(error) => {
                tracing::error!(error = %format!("{error:#}"), "rotated coordinator tokens refused; keeping the current ones")
            }
        }
    }
}

async fn shutdown() {
    let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(term) => term,
        Err(_) => return std::future::pending().await,
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    nanosiem_lake_worker::process_limits::initialize()?;
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .json()
        .try_init();
    let mut args = std::env::args().skip(1);
    let first = args.next().context(USAGE)?;
    if first == "--help" {
        println!("{USAGE}");
        return Ok(());
    }
    let tenant: Uuid = first.parse().context(USAGE)?;
    let listen: SocketAddr = args.next().context("listen address required")?.parse()?;
    let credential_file = PathBuf::from(args.next().context("tenant R2 credential file required")?);
    let token_file = PathBuf::from(args.next().context("coordinator token file required")?);
    let scratch = PathBuf::from(args.next().context("absolute scratch directory required")?);
    if args.next().is_some() || tenant.is_nil() || !scratch.is_absolute() {
        bail!("invalid lean coordinator arguments");
    }
    let reload_secs: u64 = match std::env::var("NANO_LEAN_COORDINATOR_CREDENTIAL_RELOAD_SECONDS") {
        Ok(value) => value
            .parse()
            .context("NANO_LEAN_COORDINATOR_CREDENTIAL_RELOAD_SECONDS")?,
        Err(_) => 60,
    };
    ensure!(
        (5..=3600).contains(&reload_secs),
        "credential reload interval must be 5..=3600 s"
    );
    let identity_token_file = match std::env::var_os(IDENTITY_TOKEN_ENV) {
        None => None,
        Some(value) if value.is_empty() => bail!("{IDENTITY_TOKEN_ENV} is set but empty"),
        Some(value) => Some(PathBuf::from(value)),
    };
    let (location, bytes) = read_location(&credential_file, tenant)?;
    let auth = read_auth(&token_file, identity_token_file.as_deref())?;
    let store = Arc::new(S3ObjectStore::new(&location)?);
    tokio::spawn(reload_credentials(
        store.clone(),
        credential_file,
        tenant,
        location,
        bytes,
        Duration::from_secs(reload_secs),
    ));
    let objects: Arc<dyn nanosiem_lake_worker::parts::part_log::ObjectStore> = store;
    let identity_writer = auth.has_identity_writer();
    let state = LeanCoordinatorState::with_auth(tenant, auth, objects, scratch)?;
    tokio::spawn(reload_tokens(
        state.clone(),
        token_file,
        identity_token_file,
        Duration::from_secs(reload_secs),
    ));
    let app = router(state).route(
        "/healthz",
        axum::routing::get(|| async { axum::Json(serde_json::json!({"status": "ok"})) }),
    );
    let socket = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%tenant, %listen, identity_writer, "lean enrichment coordinator listening");
    axum::serve(socket, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NAN-3503: both token files are read, trimmed and validated together;
    /// errors never echo token material.
    #[test]
    fn read_auth_validates_both_token_files() {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, text: &str| {
            let path = dir.path().join(name);
            std::fs::write(&path, text).unwrap();
            path
        };
        let full = write("full", "tenant-full-coordinator-bearer-token-0001\n");
        let identity = write("identity", "tenant-identity-writer-bearer-token-0001\n");
        let same = write("same", " tenant-full-coordinator-bearer-token-0001 ");
        let short = write("short", "short-identity-token");
        let missing = dir.path().join("missing");
        assert!(!read_auth(&full, None).unwrap().has_identity_writer());
        assert!(read_auth(&full, Some(&identity))
            .unwrap()
            .has_identity_writer());
        for (bad, what) in [
            (same.as_path(), "must differ"),
            (short.as_path(), "too short"),
            (missing.as_path(), "unreadable"),
        ] {
            let error = format!("{:#}", read_auth(&full, Some(bad)).unwrap_err());
            assert!(error.contains(what), "{error}");
            assert!(!error.contains("bearer-token"), "{error}");
        }
    }
}

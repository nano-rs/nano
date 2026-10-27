// SPDX-License-Identifier: AGPL-3.0-or-later

//! `nanosiem-lake-cell`: the lean-lake cell supervisor (NAN-2871).
//!
//! ```text
//! nanosiem-lake-cell supervise --config /etc/nano-cell/cell.json
//! nanosiem-lake-cell probe [--write] [--config /etc/nano-cell/cell.json]
//! nanosiem-lake-cell trusted-local init --out <dir> [...]   (NAN-3492; see trusted_local.rs)
//! ```

use anyhow::Context;
use nanosiem_lake_cell::config::CellConfig;
use nanosiem_lake_cell::router::{self, Router};
use nanosiem_lake_cell::secrets::{ControlPlaneKeySource, DirKeySource, KeySource};
use nanosiem_lake_cell::supervisor::Supervisor;
use std::sync::Arc;

/// SIGTERM: how long the router waits for open connections to finish their
/// in-flight request after the drain window (the platform's derived
/// terminationGracePeriodSeconds keeps a 24 s margin past the drain).
const ROUTER_CLOSE_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

fn usage() -> ! {
    eprintln!("usage: nanosiem-lake-cell supervise --config <file> | probe [--write] [--config <file>] | features | trusted-local init --out <dir> [...]");
    std::process::exit(2)
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("features") => {
            // Read by the image build into the nanosiem.io/cell-features label.
            println!("{}", nanosiem_lake_cell::features::label());
            Ok(())
        }
        Some("trusted-local") => std::process::exit(nanosiem_lake_cell::trusted_local::main(&args[1..])),
        Some("probe") => {
            // Before any runtime: the probe forks.
            let write = args.iter().any(|a| a == "--write");
            let input = match args.windows(2).find(|w| w[0] == "--config").map(|w| w[1].clone()) {
                Some(path) => {
                    let cfg: CellConfig = serde_json::from_slice(&std::fs::read(&path).with_context(|| path.clone())?)
                        .with_context(|| format!("parse {path}"))?;
                    cfg.validate()?;
                    nanosiem_lake_cell::probe::ProbeInput::from_config(&cfg, write)
                }
                None => nanosiem_lake_cell::probe::ProbeInput { write, ..Default::default() },
            };
            let report = nanosiem_lake_cell::probe::run(&input);
            if input.trusted_local && report.landlock_abi <= 0 {
                eprintln!("WARNING: Landlock unavailable; trusted-local single-tenant mode continues with uid separation, seccomp and namespaces. Enable Landlock in the host kernel LSM list for filesystem confinement.");
            }
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Some("supervise") => {
            let path = args.windows(2).find(|w| w[0] == "--config").map(|w| w[1].clone()).unwrap_or_else(|| usage());
            let cfg: CellConfig = serde_json::from_slice(&std::fs::read(&path).with_context(|| path.clone())?)
                .with_context(|| format!("parse {path}"))?;
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                )
                .json()
                .init();
            tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(supervise(cfg))
        }
        _ => usage(),
    }
}

async fn supervise(cfg: CellConfig) -> anyhow::Result<()> {
    let keys: Arc<dyn KeySource> = match (&cfg.control_url, &cfg.cell_identity_file, &cfg.dev_key_dir) {
        (Some(url), Some(id), _) => Arc::new(ControlPlaneKeySource::new(url.clone(), cfg.cell_id.clone(), id.clone())?),
        (None, _, Some(dir)) => {
            tracing::warn!("using the development key directory; not for production");
            Arc::new(DirKeySource::new(dir.clone())?)
        }
        _ => anyhow::bail!("configure control_url + cell_identity_file (or dev_key_dir)"),
    };
    // NAN-3523: before any child exists, so every tenant and warm process
    // ranks above the supervisor for the OOM killer.
    nanosiem_lake_cell::oom::protect_supervisor(cfg.resources.tenant_oom_score_adj);
    let sup = Supervisor::new(cfg.clone(), keys)?;
    if let Err(e) = sup.reload_placement().await {
        tracing::warn!(error = %e, "no initial placement; starting empty");
    }
    sup.start_background();
    // NAN-3000: push status + verified purges to the platform, with the same
    // identity as the bootstrap route (projected SA token, aud nano-lake-cell).
    match (&cfg.control_url, &cfg.cell_identity_file) {
        (Some(url), Some(id)) => match nanosiem_lake_cell::report::Reporter::new(url, &cfg.cell_id, id.clone()) {
            Ok(reporter) => {
                tracing::info!(url = reporter.url(), "status reporter started");
                let src: Arc<dyn nanosiem_lake_cell::report::StatusSource> = sup.clone();
                let (notify, s2) = (sup.report_notify(), sup.clone());
                tokio::spawn(reporter.run(src, notify, move || s2.is_halted()));
            }
            // Never a boot failure: tenants keep running, purges stay in the ledger.
            Err(e) => tracing::error!(error = %e, "status reporter not started; purges are recorded but not pushed"),
        },
        _ => tracing::warn!("no control_url + cell_identity_file: status and purge reports are not pushed"),
    }
    let router = Router::new(sup.clone())?;
    let mut tasks = Vec::new();
    if let Some(addr) = &cfg.listen_tcp {
        let l = tokio::net::TcpListener::bind(addr).await.with_context(|| format!("bind {addr}"))?;
        tracing::info!(%addr, "router listening (tcp)");
        tasks.push(tokio::spawn(router::serve_tcp(router.clone(), l)));
    }
    if let Some(p) = &cfg.listen_unix {
        let _ = std::fs::remove_file(p);
        let l = tokio::net::UnixListener::bind(p).with_context(|| format!("bind {}", p.display()))?;
        tracing::info!(path = %p.display(), "router listening (unix)");
        tasks.push(tokio::spawn(router::serve_unix(router.clone(), l)));
    }
    let r2 = router.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tick.tick().await;
            if let Err(e) = r2.reload_token() {
                tracing::error!(error = %e, "router token reload failed; keeping the previous token");
            }
        }
    });
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = term.recv() => tracing::info!("SIGTERM: stopping tenant processes"),
        _ = tokio::signal::ctrl_c() => tracing::info!("SIGINT: stopping tenant processes"),
    }
    // NAN-3004: with `zero_downtime_roll`, withdraw readiness and release the
    // writers first, keep serving queries through the drain window (every
    // response now carries `Connection: close`, so callers' pooled
    // connections move to the pod that stays).
    sup.handover_quiesce().await;
    // Then stop accepting and close the remaining connections gracefully
    // (in-flight requests finish) while the tenant processes still run: a
    // request on a keep-alive connection pinned here must never meet a
    // stopped cell (503) or a socket reset by process exit (502).
    let open = router.close(ROUTER_CLOSE_WAIT).await;
    if open > 0 {
        tracing::warn!(open, "router connections still open at the close deadline");
    }
    tracing::info!("router closed; stopping tenant processes");
    sup.drain_all().await;
    for t in tasks {
        t.abort();
    }
    Ok(())
}

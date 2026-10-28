// SPDX-License-Identifier: AGPL-3.0-or-later
//! Self-hosted platform feeds (NAN-4759 part B): the sovereign and open-core
//! `lean-platform-feeds` service and the `nano feeds update` backend.
//!
//! - `serve [--once]`: keep `<bundle dir>` holding a bundle (an empty one
//!   until the first import) and every tenant's `<policy root>/<T>/policy.json`
//!   composed from `<grants dir>/<T>.json` and the installed bundle; GC
//!   bundles no policy names any more. No network IO: runtime makes no egress.
//! - `ready`: every tenant has a policy whose bundle the cell's own source
//!   opens and verifies (the compose healthcheck the cell waits on).
//! - `status`: the installed feeds and their freshness, as JSON.
//! - `import --file <bundle>`: verify a portable signed bundle and install it
//!   atomically. The serving loop composes the next policy revision within one
//!   interval, and each tenant's ingest rotates to it within its 30 s refresh,
//!   without a restart.
use anyhow::{bail, ensure, Result};
use chrono::{Duration, Utc};
use nanosiem_lake_worker::lean_platform_feeds::{self as feeds, Layout};
use nanosiem_lake_worker::lean_platform_policy as layout;
use std::{collections::BTreeMap, ffi::OsString, os::unix::fs::PermissionsExt, path::PathBuf};

const USAGE: &str = "usage: lake_platform_feeds serve [--once] | ready | status | import --file <portable bundle> | check-current --file <API response>";
/// The default grants dir: rendered by `nanosiem-lake-cell trusted-local init`
/// (one all-bundled grants file per tenant), mounted read-only.
const GRANTS_DIR: &str = "/etc/nano-platform-grants";

fn env_path(name: &str, default: &str) -> PathBuf {
    std::env::var_os(name).map_or_else(|| PathBuf::from(default), PathBuf::from)
}

fn layout_from_env() -> Result<Layout> {
    let layout = Layout {
        bundle_dir: env_path("PLATFORM_BUNDLE_DIR", layout::BUNDLE_DIR),
        policy_root: env_path("PLATFORM_POLICY_ROOT", layout::POLICY_ROOT),
        grants_dir: env_path("PLATFORM_GRANTS_DIR", GRANTS_DIR),
    };
    layout.validate()?;
    Ok(layout)
}

fn ensure_policy_root(layout: &Layout) -> Result<()> {
    match std::fs::symlink_metadata(&layout.policy_root) {
        Ok(meta) => ensure!(meta.file_type().is_dir(), "policy root must be a real directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(&layout.policy_root)?;
            std::fs::set_permissions(&layout.policy_root, std::fs::Permissions::from_mode(0o755))?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn serve(once: bool) -> Result<()> {
    if !once {
        install_stop_signal_handlers();
    }
    let layout = layout_from_env()?;
    let interval = 15;
    let gc_grace = Duration::hours(1);
    ensure_policy_root(&layout)?;
    feeds::ensure_bundle_dir(&layout.bundle_dir)?;
    let mut unreferenced = BTreeMap::new();
    loop {
        let failed = match layout.cycle(Utc::now(), &mut unreferenced, gc_grace) {
            Ok(report) => {
                println!("{}", serde_json::to_string(&report)?);
                report.tenant_errors > 0
            }
            Err(error) => {
                eprintln!("{}", serde_json::json!({"event": "platform_feeds_cycle_failed", "error": format!("{error:#}")}));
                true
            }
        };
        if once {
            ensure!(!failed, "platform feeds cycle failed");
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(interval as u64));
    }
}

/// Verify a portable signed bundle and install it. Verification is the
/// shared NAN-4759 verify library (part A); nothing is written before it
/// passes.
fn import(file: PathBuf) -> Result<()> {
    let layout = layout_from_env()?;
    ensure!(file.is_absolute(), "--file must be an absolute path");
    let receipt = feeds::import_file(&layout.bundle_dir, &file,
        &nanosiem_core::platform_enrichment::portable::KeyRing::production(), Utc::now())?;
    println!("{}", serde_json::to_string(&serde_json::json!({
        "event": "platform_feeds_imported",
        "bundle_sha256": receipt.bundle_sha256,
        "source_sha256": receipt.source_sha256,
        "sequence": receipt.sequence,
        "revisions": receipt.revisions,
        "hard_expiry": receipt.valid_until,
    }))?);
    Ok(())
}

extern "C" fn exit_on_stop_signal(_: libc::c_int) {
    // Async-signal-safe. Every publication stages a new inode and renames it,
    // so a stop never leaves a partial bundle, receipt or policy behind.
    unsafe { libc::_exit(0) }
}

fn install_stop_signal_handlers() {
    for signal in [libc::SIGTERM, libc::SIGINT] {
        let handler = exit_on_stop_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        if unsafe { libc::signal(signal, handler) } == libc::SIG_ERR {
            eprintln!("platform feeds: cannot install stop signal handler");
            std::process::exit(1);
        }
    }
}

fn main() -> Result<()> {
    nanosiem_lake_worker::process_limits::initialize()?;
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let args: Vec<Option<&str>> = args.iter().map(|a| a.to_str()).collect();
    match args.as_slice() {
        [Some("--help")] => {
            println!("{USAGE}");
            Ok(())
        }
        [Some("serve")] => serve(false),
        [Some("serve"), Some("--once")] => serve(true),
        [Some("ready")] => layout_from_env()?.ready(),
        [Some("status")] => {
            let layout = layout_from_env()?;
            println!("{}", serde_json::to_string_pretty(&feeds::status(&layout.bundle_dir, Utc::now())?)?);
            Ok(())
        }
        [Some("import"), Some("--file"), Some(file)] => import(PathBuf::from(file)),
        [Some("check-current"), Some("--file"), Some(file)] => {
            let file = PathBuf::from(file);
            ensure!(file.is_absolute(), "--file must be an absolute path");
            let layout = layout_from_env()?;
            let ring = nanosiem_core::platform_enrichment::portable::KeyRing::production();
            if let Some(url) = feeds::check_current(&layout.bundle_dir, &file, &ring)? {
                println!("{url}");
            }
            Ok(())
        }
        _ => bail!("{USAGE}"),
    }
}

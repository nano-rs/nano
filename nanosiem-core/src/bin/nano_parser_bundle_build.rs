// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tenant parser-bundle build Job entrypoint (NAN-2604).
//!
//! ```text
//! nano-parser-bundle-build generate --input /input --work /work
//! nano-parser-bundle-build finalize --work /work --results /results --out /out \
//!     [--termination-log /dev/termination-log]
//! ```
//!
//! `finalize` reads `NANO_RUNTIME_IMAGE_DIGEST` (the digest the Job pinned the
//! Vector stage to) and refuses a build whose `build.json` names another.
//! When the Vector stage found the in-cluster Kubernetes API reachable (and
//! nothing else), finalize makes one anonymous `GET /api` to prove access is
//! refused (NAN-2987, see `build::SandboxProbe`).
//!
//! ```text
//! nano-parser-bundle-build add-platform-audit-lane --base base.tar.gz --out base-audit.tar.gz
//! ```
//!
//! derives the platform base carrying the NAN-2999 `audit` plumbing lane
//! (lean tenants' platform audit, delivered by the platform) and prints the new
//! archive's sha256, bytes and `hecSources` as JSON.
//!
//! ```text
//! nano-parser-bundle-build add-bronze-row-contract --base base.tar.gz --out base-nan3339.tar.gz
//! ```
//!
//! derives the platform base whose bronze rows follow the NAN-3339 fixed row
//! contract (`time` + the OCSF row as one JSON string), printing the same JSON.
//!
//! ```text
//! nano-parser-bundle-build upgrade-bronze-buffer-bytes --base base.tar.gz --out base-nan3523.tar.gz
//! ```
//!
//! derives the platform base whose bronze sink buffer is bounded by bytes
//! (NAN-3523: only that section of the two `_ocsf_sink.toml` copies changes),
//! printing the same JSON.
//!
//! Both stages exit 0 once they have recorded a verdict — a failed build is a
//! normal outcome carried in the report — and 1 only when they could not
//! read or write their mounts.

use std::path::PathBuf;

use nanosiem_core::parsers::tenant_bundle::build;

fn flag(args: &[String], name: &str) -> Option<PathBuf> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| PathBuf::from(&pair[1]))
}

fn required(args: &[String], name: &str) -> Result<PathBuf, String> {
    flag(args, name).ok_or_else(|| format!("missing {name}"))
}

fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("generate") => {
            let outcome =
                build::run_generate(&required(args, "--input")?, &required(args, "--work")?)
                    .map_err(|e| e.to_string())?;
            let status = if outcome.ok() { "ok" } else { "failed" };
            eprintln!("generate: {status}");
            Ok(())
        }
        Some("finalize") => {
            // Required: finalize refuses a build whose Vector stage ran in any
            // image other than the one build.json pins.
            let digest = std::env::var("NANO_RUNTIME_IMAGE_DIGEST")
                .map_err(|_| "NANO_RUNTIME_IMAGE_DIGEST is required".to_string())?;
            // NAN-2987: the sandbox may reach the in-cluster Kubernetes API and
            // nothing else; finalize (same pod network) checks its own token
            // mount and that anonymous GET /api is refused.
            let probe = |results: &std::path::Path, egress: Option<&str>| {
                build::SandboxProbe::gather(
                    results,
                    egress,
                    |name| std::env::var(name).ok(),
                    std::path::Path::new(build::SERVICE_ACCOUNT_TOKEN_PATH).exists(),
                    build::anonymous_api_status,
                )
            };
            let summary = build::run_finalize_with_sandbox(
                &required(args, "--work")?,
                &required(args, "--results")?,
                &required(args, "--out")?,
                flag(args, "--termination-log").as_deref(),
                Some(digest.as_str()),
                &probe,
                &mut std::io::stdout().lock(),
            )
            .map_err(|e| e.to_string())?;
            eprintln!("finalize: {:?}", summary.verdict);
            Ok(())
        }
        Some(command @ ("add-platform-audit-lane" | "upgrade-platform-audit-lane")) => {
            use nanosiem_core::parsers::tenant_bundle::{archive, overlay, platform_audit_lane};
            use sha2::{Digest, Sha256};
            let base = std::fs::read(required(args, "--base")?).map_err(|e| e.to_string())?;
            let tree = archive::unpack(&base).map_err(|e| e.to_string())?;
            // NAN-3304: `upgrade-` swaps a base's existing lane for the current one.
            let with = if command == "add-platform-audit-lane" {
                platform_audit_lane::add_platform_audit_lane(&tree)
            } else {
                platform_audit_lane::upgrade_platform_audit_lane(&tree)
            }
            .map_err(|e| e.to_string())?;
            let packed = archive::pack(&with).map_err(|e| e.to_string())?;
            std::fs::write(required(args, "--out")?, &packed).map_err(|e| e.to_string())?;
            println!("{}", serde_json::json!({
                "baseSha256": hex::encode(Sha256::digest(&base)),
                "sha256": hex::encode(Sha256::digest(&packed)),
                "bytes": packed.len(),
                "hecSources": overlay::platform_slugs(&with).map_err(|e| e.to_string())?,
            }));
            Ok(())
        }
        Some("add-bronze-row-contract") => {
            // NAN-3339: the fixed bronze row contract (one shape per bronze row).
            use nanosiem_core::parsers::tenant_bundle::{archive, bronze_row_contract, overlay};
            use sha2::{Digest, Sha256};
            let base = std::fs::read(required(args, "--base")?).map_err(|e| e.to_string())?;
            let tree = archive::unpack(&base).map_err(|e| e.to_string())?;
            let with = bronze_row_contract::add_bronze_row_contract(&tree).map_err(|e| e.to_string())?;
            let packed = archive::pack(&with).map_err(|e| e.to_string())?;
            std::fs::write(required(args, "--out")?, &packed).map_err(|e| e.to_string())?;
            println!("{}", serde_json::json!({
                "baseSha256": hex::encode(Sha256::digest(&base)),
                "sha256": hex::encode(Sha256::digest(&packed)),
                "bytes": packed.len(),
                "hecSources": overlay::platform_slugs(&with).map_err(|e| e.to_string())?,
            }));
            Ok(())
        }
        Some("upgrade-source-ack") => {
            use nanosiem_core::parsers::tenant_bundle::{archive, source_ack, overlay};
            use sha2::{Digest, Sha256};
            let base = std::fs::read(required(args, "--base")?).map_err(|e| e.to_string())?;
            let tree = archive::unpack(&base).map_err(|e| e.to_string())?;
            let with = source_ack::upgrade_source_ack(&tree).map_err(|e| e.to_string())?;
            let packed = archive::pack(&with).map_err(|e| e.to_string())?;
            std::fs::write(required(args, "--out")?, &packed).map_err(|e| e.to_string())?;
            println!("{}", serde_json::json!({
                "baseSha256": hex::encode(Sha256::digest(&base)),
                "sha256": hex::encode(Sha256::digest(&packed)),
                "bytes": packed.len(),
                "hecSources": overlay::platform_slugs(&with).map_err(|e| e.to_string())?,
            }));
            Ok(())
        }
        Some("upgrade-bronze-buffer-bytes") => {
            // NAN-3523: the byte-bounded bronze sink buffer.
            use nanosiem_core::parsers::tenant_bundle::{archive, bronze_buffer_bytes, overlay};
            use sha2::{Digest, Sha256};
            let base = std::fs::read(required(args, "--base")?).map_err(|e| e.to_string())?;
            let tree = archive::unpack(&base).map_err(|e| e.to_string())?;
            let with = bronze_buffer_bytes::upgrade_bronze_buffer_bytes(&tree).map_err(|e| e.to_string())?;
            let packed = archive::pack(&with).map_err(|e| e.to_string())?;
            std::fs::write(required(args, "--out")?, &packed).map_err(|e| e.to_string())?;
            println!("{}", serde_json::json!({
                "baseSha256": hex::encode(Sha256::digest(&base)),
                "sha256": hex::encode(Sha256::digest(&packed)),
                "bytes": packed.len(),
                "hecSources": overlay::platform_slugs(&with).map_err(|e| e.to_string())?,
            }));
            Ok(())
        }
        _ => Err("usage: nano-parser-bundle-build generate|finalize|add-platform-audit-lane|upgrade-platform-audit-lane|add-bronze-row-contract|upgrade-bronze-buffer-bytes|upgrade-source-ack …".into()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(message) = run(&args) {
        eprintln!("NANO_PARSER_BUNDLE_BUILD_ERROR {message}");
        std::process::exit(1);
    }
}

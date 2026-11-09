// SPDX-License-Identifier: AGPL-3.0-or-later

//! Export the merged OpenAPI spec to JSON on stdout.
//!
//! Used to refresh `docs/api/openapi.json` for downstream tooling that wants
//! the actual rendered spec (e.g., the docs RAG generator), without standing
//! up a running API server. Wraps `nanosiem_api::openapi::build_openapi`.
//! The published `docs/api/openapi.json` is the OPEN edition's spec, so it is
//! exported without features (`tools/export-openapi.sh`).
//!
//! With `--desktop-wire` it instead emits the scoped `/api/hunts` spec the
//! desktop's generated TypeScript wire types are built from (NAN-2263) —
//! `nanosiem_api::openapi::desktop_wire_spec`. The hunts surface is
//! enterprise-only, so that mode needs the enterprise build and fails loudly
//! without it rather than emitting an empty spec.
//!
//! Usage:
//!   cargo run --bin export_openapi > docs/api/openapi.json
//!   cargo run --features enterprise --bin export_openapi -- --desktop-wire \
//!     > nano-desktop/openapi/hunts-wire.json

use nanosiem_api::openapi::build_openapi;

fn main() -> anyhow::Result<()> {
    if std::env::args().any(|arg| arg == "--desktop-wire") {
        #[cfg(feature = "enterprise")]
        {
            let spec = nanosiem_api::openapi::desktop_wire_spec();
            println!("{}", serde_json::to_string_pretty(&spec)?);
            return Ok(());
        }
        #[cfg(not(feature = "enterprise"))]
        anyhow::bail!(
            "--desktop-wire exports the enterprise-only hunts surface; \
             rerun with `cargo run -p nanosiem-api --features enterprise --bin export_openapi -- --desktop-wire`"
        );
    }
    let spec = build_openapi();
    println!("{}", spec.to_pretty_json()?);
    Ok(())
}

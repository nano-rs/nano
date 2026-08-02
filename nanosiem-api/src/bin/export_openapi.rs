// SPDX-License-Identifier: AGPL-3.0-or-later

//! Export the merged OpenAPI spec to JSON on stdout.
//!
//! Used to refresh `docs/api/openapi.json` for downstream tooling that wants
//! the actual rendered spec (e.g., the docs RAG generator), without standing
//! up a running API server. Wraps `nanosiem_api::openapi::build_openapi`.
//!
//! With `--desktop-wire` it instead emits the scoped `/api/hunts` spec the
//! desktop's generated TypeScript wire types are built from (NAN-2263) —
//! `nanosiem_api::openapi::desktop_wire_spec`.
//!
//! Usage:
//!   cargo run --bin export_openapi > docs/api/openapi.json
//!   cargo run --bin export_openapi -- --desktop-wire > nano-desktop/openapi/hunts-wire.json

use nanosiem_api::openapi::{build_openapi, desktop_wire_spec};

fn main() -> anyhow::Result<()> {
    if std::env::args().any(|arg| arg == "--desktop-wire") {
        println!("{}", serde_json::to_string_pretty(&desktop_wire_spec())?);
        return Ok(());
    }
    let spec = build_openapi();
    println!("{}", spec.to_pretty_json()?);
    Ok(())
}

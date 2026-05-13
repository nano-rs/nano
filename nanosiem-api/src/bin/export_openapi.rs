// SPDX-License-Identifier: AGPL-3.0-or-later

//! Export the merged OpenAPI spec to JSON on stdout.
//!
//! Used to refresh `docs/api/openapi.json` for downstream tooling that wants
//! the actual rendered spec (e.g., the docs RAG generator), without standing
//! up a running API server. Wraps `nanosiem_api::openapi::build_openapi`.
//!
//! Usage:
//!   cargo run --bin export_openapi > docs/api/openapi.json

use nanosiem_api::openapi::build_openapi;

fn main() -> anyhow::Result<()> {
    let spec = build_openapi();
    println!("{}", spec.to_pretty_json()?);
    Ok(())
}

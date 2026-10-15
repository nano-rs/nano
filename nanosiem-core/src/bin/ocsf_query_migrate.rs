// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parse one saved nPL query and propose a one-time canonical OCSF 1.9 rewrite.

use std::io::{self, Read};

use anyhow::{Context, Result};
use nanosiem_core::query::migration::{
    migrate_query_to_ocsf_1_9, OCSF_CONTENT_MIGRATION_CONTRACT,
};
use nanosiem_core::query::{parse_query, PrettyPrint};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    query: String,
}

#[derive(Serialize)]
struct Response {
    schema_version: u8,
    target_contract: &'static str,
    original_query: String,
    migrated_query: String,
    changed: bool,
    replacements: std::collections::BTreeMap<String, String>,
    manual_reasons: Vec<String>,
}

fn main() -> Result<()> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let request: Request = serde_json::from_str(&input).context("invalid migration request")?;
    let mut query = parse_query(&request.query).context("invalid nPL query")?;
    let report = migrate_query_to_ocsf_1_9(&mut query);
    let migrated_query = query.pretty_print();
    let response = Response {
        schema_version: 1,
        target_contract: OCSF_CONTENT_MIGRATION_CONTRACT,
        changed: migrated_query != request.query,
        original_query: request.query,
        migrated_query,
        replacements: report.replacements,
        manual_reasons: report.manual_reasons,
    };
    println!("{}", serde_json::to_string(&response)?);
    Ok(())
}

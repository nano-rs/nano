// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3625: the platform input identity a lane's events carry (`nano_input`).
//!
//! Every ingress path already stamps the trusted Vector metadata
//! `%nano_credential_id` before the tenant lane runs:
//!
//! - push (HEC / OTLP / Nano HTTPS through the tenant Worker): the
//!   authenticated ingest credential's UUID, from the Worker-built
//!   `X-Nano-Credential-Id` header (`workers/hosted-ingest/prepare-config.py`,
//!   `shared_worker_build_context.rs`);
//! - pull: `pull:<pull_source_id>`, from the platform pull stamp
//!   (`tenant_bundle::pull::render_stamp`);
//! - connector feeds: the feed's platform-held per-feed ingest credential
//!   (NAN-3490), so a feed is the push input of that credential.
//!
//! Tenant VRL cannot write `%` metadata (the bundle overlay guard refuses any
//! metadata write outside the fixed combine restore), and a payload field such
//! as `.metadata.nano_input` is never read, so the identity cannot be forged
//! from inside a lane or from an event body. `nano_input` is a pure function
//! of `%nano_credential_id`: `push:<credential_id>` or `pull:<source_id>`. No
//! new stamp or stored field is added, so existing lanes render and store
//! byte-identically.

use uuid::Uuid;

/// Trusted Vector metadata the platform stamps on every ingress path.
pub const METADATA: &str = "nano_credential_id";
/// At most this many inputs per route branch.
pub const MAX_INPUTS: usize = 64;

/// Canonical `push:<uuid>` / `pull:<uuid>` (lowercase, hyphenated).
pub fn canonical(value: &str) -> Result<String, String> {
    let (kind, id) = value
        .trim()
        .split_once(':')
        .ok_or("An input is push:<credential id> or pull:<pull source id>")?;
    if !["push", "pull"].contains(&kind) {
        return Err(if kind == "feed" {
            "Choose a connector feed by its ingest credential (push:<credential id>)".into()
        } else {
            "An input is push:<credential id> or pull:<pull source id>".into()
        });
    }
    // Only the canonical hyphenated form: `Uuid::parse_str` also takes
    // braced/URN/simple spellings, which would never match the stamp.
    let parsed = Uuid::try_parse(id)
        .ok()
        .filter(|uuid| uuid.hyphenated().to_string() == id.to_ascii_lowercase())
        .ok_or("An input id must be a hyphenated UUID")?;
    Ok(format!("{kind}:{}", parsed.hyphenated()))
}

/// The `%nano_credential_id` value the platform stamps for a canonical input.
pub fn stamped(canonical: &str) -> &str {
    canonical.strip_prefix("push:").unwrap_or(canonical)
}

/// The canonical input of a stamped `%nano_credential_id`, if it is one.
pub fn of_stamp(stamp: &str) -> Option<String> {
    let candidate = if stamp.starts_with("pull:") {
        stamp.to_string()
    } else {
        format!("push:{stamp}")
    };
    canonical(&candidate)
        .ok()
        .filter(|value| stamped(value) == stamp)
}

/// Validated, de-duplicated canonical inputs of one route branch.
pub fn parse_list(value: &serde_json::Value) -> Result<Vec<String>, String> {
    let values = value
        .as_array()
        .ok_or("Route inputs must be an array of push:/pull: input ids")?;
    if values.is_empty() || values.len() > MAX_INPUTS {
        return Err(format!("Route inputs require 1–{MAX_INPUTS} input ids"));
    }
    let mut out: Vec<String> = Vec::new();
    for value in values {
        let input = canonical(value.as_str().ok_or("Route inputs must be text")?)?;
        if !out.contains(&input) {
            out.push(input);
        }
    }
    Ok(out)
}

/// The read-only VRL condition matching any of `inputs`. It reads only the
/// platform metadata, never the event body.
pub fn predicate(inputs: &[String]) -> String {
    let checks: Vec<String> = inputs
        .iter()
        .map(|input| {
            format!(
                "%{METADATA} == {}",
                serde_json::to_string(stamped(input)).expect("string serialization")
            )
        })
        .collect();
    format!("({})", checks.join(" || "))
}

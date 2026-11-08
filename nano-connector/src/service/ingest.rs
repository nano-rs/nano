// SPDX-License-Identifier: AGPL-3.0-or-later

//! Where a feed's events are delivered, and with which ingest token.
//!
//! Every feed posts to the deployment's local Vector HEC listener
//! (`splunk_hec_ingest`, `:8088`) with the platform ingest credential
//! (`NANO_PLATFORM_INGEST_TOKEN`, NAN-4907): [`StaticIngest`]. nano-api lists
//! it in Vector's tokens file as a MULTIPLEX credential (route `*`), so
//! `hec_normalize` routes each envelope on its own `sourcetype`, which is the
//! feed stream's rendered `source_type`: one runner credential serves every
//! feed and every lane, each event keeping its per-feed source.
//!
//! Never the install token (`VECTOR_AUTH_TOKEN`): on a fresh install it is
//! strict (refused while unbound), and once bound every envelope would be
//! rewritten to that one source. [`resolve_ingest_token`] refuses it.
//!
//! Seam for per-source ingest tokens (NAN-4907): a token bound to the feed's
//! source, read from the same `valid_tokens_file` Vector uses, so revoking
//! one feed does not rotate the install token. That lands as another
//! [`IngestRoute`] implementation keyed by [`FeedDefinition::feed_id`] /
//! [`FeedDefinition::source_type`]; the runner, the HEC sink and the store do
//! not change.

use super::feed::{FeedDefinition, Secret};

pub trait IngestRoute: Send + Sync {
    /// `(HEC base or event URL, ingest token)` for one run of `feed`.
    fn route(&self, feed: &FeedDefinition) -> Result<(String, Secret), String>;
}

/// One URL and one token for every feed.
pub struct StaticIngest {
    pub url: String,
    pub token: Secret,
}

impl IngestRoute for StaticIngest {
    fn route(&self, _feed: &FeedDefinition) -> Result<(String, Secret), String> {
        if self.token.expose().trim().is_empty() {
            return Err("ingest token is not configured (CONNECTOR_HEC_TOKEN / CONNECTOR_HEC_TOKEN_FILE)".into());
        }
        Ok((self.url.clone(), self.token.clone()))
    }
}

/// The runner's ingest token from its environment, in order:
/// `CONNECTOR_HEC_TOKEN_FILE`, `CONNECTOR_HEC_TOKEN`, `NANO_PLATFORM_INGEST_TOKEN`.
/// Refused when it equals the install token (`VECTOR_AUTH_TOKEN`, when the
/// runner can see it) or is missing. `read_file` reads a token file.
pub fn resolve_ingest_token(
    env: &dyn Fn(&str) -> Option<String>,
    read_file: &dyn Fn(&str) -> Result<String, String>,
) -> Result<Secret, String> {
    let token = if let Some(path) = env("CONNECTOR_HEC_TOKEN_FILE") {
        read_file(&path).map_err(|e| format!("CONNECTOR_HEC_TOKEN_FILE: {e}"))?.trim().to_string()
    } else if let Some(t) = env("CONNECTOR_HEC_TOKEN") {
        t.trim().to_string()
    } else if let Some(t) = env("NANO_PLATFORM_INGEST_TOKEN") {
        t.trim().to_string()
    } else {
        String::new()
    };
    if token.is_empty() {
        return Err("the runner needs the platform ingest credential: set NANO_PLATFORM_INGEST_TOKEN \
                    (or CONNECTOR_HEC_TOKEN / CONNECTOR_HEC_TOKEN_FILE to it)"
            .into());
    }
    if env("VECTOR_AUTH_TOKEN").is_some_and(|install| install.trim() == token) {
        return Err("the runner's ingest token is the install token (VECTOR_AUTH_TOKEN); use the platform \
                    ingest credential NANO_PLATFORM_INGEST_TOKEN instead (a strict install token is refused, \
                    a bound one rewrites every event to one source)"
            .into());
    }
    Ok(Secret::new(token))
}

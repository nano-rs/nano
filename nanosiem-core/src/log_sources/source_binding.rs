// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5789: the one check every writer of a fetch log source runs (the
//! log-source service, the parser service, repository parser import).
//!
//! A fetch source (kafka, S3/SQS, FDR, Pub/Sub, Event Hubs) reads from its
//! source configuration's route, so it must name an EXISTING configuration of
//! the SAME type. A source that is (or is being made) live must also name a
//! DEPLOYED one: otherwise the render leaves it out and its ingest stops.

use sqlx::PgPool;
use uuid::Uuid;

use super::ingest_transport::{canonical, dispatch_compatible};
use crate::parsers::is_fetch_source_type;

/// Why a binding is refused. Always about `dispatch_source_config_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingError {
    pub field: &'static str,
    pub message: String,
}

impl BindingError {
    fn new(message: String) -> Self {
        Self { field: "dispatch_source_config_id", message }
    }
}

/// What the binding points at, as read from `source_configurations`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundConfig {
    pub config_type: String,
    pub deployed: bool,
}

/// The pure half. `config` is `None` when the binding names no existing row.
pub fn check_binding(
    kind: &str,
    source_type: &str,
    binding: Option<Uuid>,
    config: Option<&BoundConfig>,
    must_be_deployed: bool,
) -> Result<(), BindingError> {
    if kind == "enrichment" || !is_fetch_source_type(source_type) {
        return Ok(());
    }
    let method = canonical(source_type).unwrap_or(source_type);
    let Some(id) = binding else {
        return Err(BindingError::new(format!(
            "a {method} log source needs a source configuration: set dispatch_source_config_id to a \
             {method} source configuration (create one first if none exists), or use source_type \"routed\""
        )));
    };
    let Some(config) = config else {
        return Err(BindingError::new(format!(
            "dispatch_source_config_id {id} does not match any source configuration"
        )));
    };
    if !dispatch_compatible(&config.config_type, method) {
        return Err(BindingError::new(format!(
            "dispatch_source_config_id {id} is a {} source configuration; a {method} log source needs a \
             {method} one",
            config.config_type
        )));
    }
    if must_be_deployed && !config.deployed {
        return Err(BindingError::new(format!(
            "source configuration {id} is not deployed, so this live {method} log source would ingest \
             nothing. Deploy the source configuration first, or disable the log source"
        )));
    }
    Ok(())
}

/// [`check_binding`] with the bound row read from PostgreSQL.
pub async fn ensure_binding(
    pool: &PgPool,
    kind: &str,
    source_type: &str,
    binding: Option<Uuid>,
    must_be_deployed: bool,
) -> Result<Result<(), BindingError>, sqlx::Error> {
    if kind == "enrichment" || !is_fetch_source_type(source_type) {
        return Ok(Ok(()));
    }
    let config = match binding {
        Some(id) => sqlx::query_as::<_, (String, bool)>(
            "SELECT config_type, deployed FROM source_configurations WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
        .map(|(config_type, deployed)| BoundConfig { config_type, deployed }),
        None => None,
    };
    Ok(check_binding(kind, source_type, binding, config.as_ref(), must_be_deployed))
}

#[cfg(test)]
#[path = "source_binding_tests.rs"]
mod tests;

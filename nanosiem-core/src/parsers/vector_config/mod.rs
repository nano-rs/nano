// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vector Configuration Manager
//!
//! Generates and deploys Vector TOML configurations from database parsers.
//!
//! # Submodules
//!
//! - [`backup`] - Backup and restore for rollback support
//! - [`credentials`] - Cleanup for retired parser-owned credential files
//! - [`deploy`] - Parser deployment and Vector reload
//! - [`parser_config`] - Per-parser TOML config generation
//! - [`redaction`] - Snapshot redaction for persisted Vector configs
//! - [`router`] - Dynamic source type router generation
//! - [`sources`] - Source-specific config generators (Kafka, S3, GCP, HEC)
//! - [`staging`] - Staging directory for validation before deployment
//! - [`validation`] - Vector validate integration via Docker

mod backup;
mod credentials;
pub mod delivery;
mod deploy;
mod parser_config;
mod publication;
pub mod redaction;
mod router;
mod sources;
mod staging;
mod validation;

pub use publication::{
    PublicationOutcome, SnapshotBundle, VectorConfigPublicationError, VectorConfigPublisher,
};
pub use redaction::redact_config_snapshot;
pub use router::{base_router_inputs, hec_normalize_present};

use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;

use super::types::Parser;

#[derive(Error, Debug)]
pub enum VectorConfigError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Failed to reload Vector: {0}")]
    ReloadFailed(String),
    #[error("Invalid config directory: {0}")]
    InvalidConfigDir(String),
    #[error("No backup available for restore")]
    NoBackupAvailable,
    #[error("Vector validation failed: {0}")]
    ValidationFailed(String),
    #[error("Staging directory error: {0}")]
    StagingError(String),
}

/// Manages Vector configuration files generated from database parsers
pub struct VectorConfigManager {
    /// Base config directory (e.g., config/vector)
    config_dir: PathBuf,
    /// Directory where parser configs are written
    parsers_dir: PathBuf,
    /// Sources directory (parent of parsers_dir). Retained for cleanup of
    /// credential files written by the removed parser-owned transport path.
    sources_dir: PathBuf,
    /// Staging directory for validation before deployment
    staging_dir: PathBuf,
    /// Backup directory for rollback support
    backup_dir: PathBuf,
    /// Directory for credential files (GCP service account JSON, etc.)
    credentials_dir: PathBuf,
    /// Serializes all deploy operations to prevent concurrent deploys from
    /// corrupting config or overwriting each other's backups.
    ///
    /// NAN-948: wrapped in `Arc` so the same lock can be shared with
    /// `SourceConfigService::update_dynamic_router`, which read-mutate-writes
    /// the same `_router.toml` outside this manager. Without the shared
    /// lock, a parser deploy and a source-config router update can
    /// interleave and lose one of the two updates.
    deploy_lock: Arc<tokio::sync::Mutex<()>>,
}

impl VectorConfigManager {
    /// Create a new config manager
    pub fn new(config_dir: impl AsRef<Path>) -> Self {
        let config_dir = config_dir.as_ref().to_path_buf();
        // Parser configs go directly in config_dir with 30- prefix for proper load order
        // (after router at 20-, before generic parser at 50-)
        let sources_dir = config_dir.join("sources");
        let parsers_dir = sources_dir.join("parsers");
        let staging_dir = config_dir.join("staging");
        let backup_dir = config_dir.join("backup");
        let credentials_dir = config_dir.join("credentials");
        Self {
            config_dir,
            parsers_dir,
            sources_dir,
            staging_dir,
            backup_dir,
            credentials_dir,
            deploy_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Create with default config directory
    pub fn with_defaults() -> Self {
        Self::new("config/vector")
    }

    /// Hand out a clone of the deploy lock so other services can serialize
    /// their `_router.toml` mutations against this manager's deploys.
    /// NAN-948 — without this shared lock, `SourceConfigService` and the
    /// parser deploy path can race on the read-mutate-write of `_router.toml`.
    pub fn deploy_lock(&self) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(&self.deploy_lock)
    }

    /// Get the base config directory
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    /// Convert parser name to a safe identifier for Vector.
    ///
    /// Delegates to [`crate::vector_naming::safe_name`] — see there for why the
    /// transformation is centralised rather than copied per subsystem
    /// (NAN-2196).
    pub(crate) fn safe_name(name: &str) -> String {
        crate::vector_naming::safe_name(name)
    }

    /// Path on disk for a parser-side credential or cert file. Lives directly
    /// under `sources_dir` with a `parsers__` prefix so it survives K8s
    /// ConfigMap key flattening — same path resolves under Docker bind-mounts,
    /// S3-synced K8s, and ConfigMap-synced K8s.
    pub(super) fn parser_creds_path(&self, filename: &str) -> PathBuf {
        self.sources_dir.join(format!("parsers__{}", filename))
    }

    /// Build a VRL route condition for a parser.
    /// Uses match_values when available (the actual source_type values the parser handles),
    /// falling back to safe_name for backward compatibility.
    fn build_route_condition(parser: &Parser) -> String {
        let values = Self::parser_source_types(parser);
        if values.len() == 1 {
            format!(".source_type == \"{}\"", values[0])
        } else {
            let list = values
                .iter()
                .map(|v| format!("\"{}\"", v))
                .collect::<Vec<_>>()
                .join(", ");
            format!("includes([{}], .source_type)", list)
        }
    }

    /// Get the source_type values a parser handles.
    /// Returns match_values if set, otherwise falls back to [safe_name].
    fn parser_source_types(parser: &Parser) -> Vec<String> {
        if let Some(ref mv) = parser.match_values {
            if !mv.is_empty() {
                return mv.clone();
            }
        }
        vec![Self::safe_name(&parser.name)]
    }

    /// Check if a parser handles a given source_type value.
    fn parser_handles_source_type(parser: &Parser, source_type: &str) -> bool {
        Self::parser_source_types(parser)
            .iter()
            .any(|v| v == source_type)
    }
}

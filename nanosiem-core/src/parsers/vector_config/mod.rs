// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vector Configuration Manager
//!
//! Generates and deploys Vector TOML configurations from database parsers.
//!
//! # Submodules
//!
//! - [`backup`] - Backup and restore for rollback support
//! - [`credentials`] - Credential file management (GCP, Kafka, TLS)
//! - [`deploy`] - Parser deployment and Vector reload
//! - [`parser_config`] - Per-parser TOML config generation
//! - [`redaction`] - Snapshot redaction for persisted Vector configs
//! - [`router`] - Dynamic source type router generation
//! - [`sources`] - Source-specific config generators (Kafka, S3, GCP, HEC)
//! - [`staging`] - Staging directory for validation before deployment
//! - [`validation`] - Vector validate integration via Docker

mod backup;
mod credentials;
mod deploy;
mod parser_config;
pub mod redaction;
mod router;
mod sources;
mod staging;
mod validation;

pub use redaction::redact_config_snapshot;
pub use router::base_router_inputs;

use std::path::{Path, PathBuf};
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
    /// Sources directory (parent of parsers_dir). Used for credential/cert files
    /// that need to live one level up from the parsers/ subdir so they survive
    /// K8s ConfigMap key flattening (see `parser_creds_path`).
    sources_dir: PathBuf,
    /// Staging directory for validation before deployment
    staging_dir: PathBuf,
    /// Backup directory for rollback support
    backup_dir: PathBuf,
    /// Directory for credential files (GCP service account JSON, etc.)
    credentials_dir: PathBuf,
    /// Absolute runtime path of the sources root (one level above parsers).
    /// Credential/cert files reference this so the same path resolves under
    /// Docker bind-mounts, S3-synced K8s, and ConfigMap-synced K8s (where keys
    /// can't contain `/` and the sync flattens subdirs as `__`).
    sources_runtime_path: String,
    /// Serializes all deploy operations to prevent concurrent deploys from
    /// corrupting config or overwriting each other's backups.
    deploy_lock: tokio::sync::Mutex<()>,
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
        let sources_runtime_path = std::env::var("VECTOR_SOURCES_RUNTIME_PATH")
            .unwrap_or_else(|_| "/etc/vector/sources".to_string());
        Self {
            config_dir,
            parsers_dir,
            sources_dir,
            staging_dir,
            backup_dir,
            credentials_dir,
            sources_runtime_path,
            deploy_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Create with default config directory
    pub fn with_defaults() -> Self {
        Self::new("config/vector")
    }

    /// Get the base config directory
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    /// Convert parser name to a safe identifier for Vector
    pub(crate) fn safe_name(name: &str) -> String {
        name.chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .collect::<String>()
            .to_lowercase()
    }

    /// Path on disk for a parser-side credential or cert file. Lives directly
    /// under `sources_dir` with a `parsers__` prefix so it survives K8s
    /// ConfigMap key flattening — same path resolves under Docker bind-mounts,
    /// S3-synced K8s, and ConfigMap-synced K8s.
    pub(super) fn parser_creds_path(&self, filename: &str) -> PathBuf {
        self.sources_dir.join(format!("parsers__{}", filename))
    }

    /// Absolute runtime path Vector should reference for a parser-side
    /// credential or cert file written via `parser_creds_path`.
    pub(super) fn parser_creds_runtime(&self, filename: &str) -> String {
        format!("{}/parsers__{}", self.sources_runtime_path, filename)
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

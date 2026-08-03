// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vector configuration validation via Docker exec.
//!
//! Validates staged configuration using `vector validate` inside the
//! Docker container, parsing output for errors and warnings.

use tokio::process::Command;

use super::staging::STAGED_CONFIG_SUBDIRS;
use super::VectorConfigError;
use super::VectorConfigManager;
use crate::parsers::types::{Parser, ValidationResult};

/// The `--config-dir` arguments for validating the staged candidate tree: the
/// staging root plus every subdirectory in [`STAGED_CONFIG_SUBDIRS`].
///
/// NAN-2305: this used to be the root and `sources/parsers` only, while the
/// running Vector is launched with four `--config-dir` arguments. Validating a
/// subset of the graph that is about to be promoted is not validation — the
/// staged `_router.toml` names each source config's `<stem>_route` transform,
/// those live in `sources/configs`, and an input naming a component the
/// validator cannot see is fatal to the whole config. Tenants running a pull
/// source had every parser deploy refused for a config that was in fact fine.
/// Derived from the same constant `stage_parsers` builds the tree from, so the
/// two cannot drift apart.
pub(super) fn staged_config_dir_args(container_staging_path: &str) -> Vec<String> {
    let mut dirs = vec![container_staging_path.to_string()];
    dirs.extend(
        STAGED_CONFIG_SUBDIRS
            .iter()
            .map(|subdir| format!("{}/{}", container_staging_path, subdir)),
    );
    dirs
}

/// Full argv for the staged `vector validate`, so the flags are assertable
/// rather than buried in a builder.
pub(super) fn validate_argv(container_name: &str, container_staging_path: &str) -> Vec<String> {
    let mut argv = vec![
        "exec".to_string(),
        container_name.to_string(),
        "vector".to_string(),
        "validate".to_string(),
        "--no-environment".to_string(),
    ];
    for dir in staged_config_dir_args(container_staging_path) {
        argv.push("--config-dir".to_string());
        argv.push(dir);
    }
    argv
}

/// Whether validation output shows the container could not SEE the staged tree
/// (a Docker Desktop bind-mount propagation lag on macOS) rather than rejecting
/// its contents.
///
/// NAN-2305: this used to gate a success path — mount trouble returned
/// `success: true` and the tree was promoted having been validated against
/// nothing. Two things were wrong with that. The signature is far too broad:
/// every staged path contains "staging", and "Failed to load" is what Vector
/// says about a file it DID find and could not parse, so a genuinely broken
/// staged config matched and was waved through. And even a correctly identified
/// mount problem is not evidence the config is good — promoting unvalidated
/// config is how a bad `_router.toml` reaches every tenant. It now only shapes
/// the error message; the result is a failure either way, and the deploy stops
/// with the running config untouched. Operators who genuinely cannot reach the
/// vector container from the api container have the explicit, documented
/// `SKIP_VECTOR_VALIDATION=true` knob.
fn looks_like_staging_mount_failure(combined_output: &str) -> bool {
    combined_output.contains("Failed to load") && combined_output.contains("staging")
}

impl VectorConfigManager {
    /// Validate staged configuration using `docker exec vector vector validate`
    /// Returns a structured validation result with errors and warnings
    pub async fn validate_staged_config(&self) -> Result<ValidationResult, VectorConfigError> {
        if !self.staging_dir.exists() {
            return Err(VectorConfigError::StagingError(
                "Staging directory does not exist - stage config first".to_string(),
            ));
        }

        // Get the container name from environment or use default
        let container_name = std::env::var("VECTOR_CONTAINER_NAME")
            .unwrap_or_else(|_| "nanosiem-vector".to_string());

        // Get the path inside the container where staging is mounted
        // By default, config/vector is mounted to /etc/vector in the container
        let container_staging_path = std::env::var("VECTOR_STAGING_PATH")
            .unwrap_or_else(|_| "/etc/vector/staging".to_string());

        // Run `vector validate` inside the Docker container against EVERY
        // directory the running Vector loads (NAN-2305) — base config, parsers,
        // source configs and sinks. Validating a subset means passing judgement
        // on a topology nobody will run; see `staged_config_dir_args`.
        let mut validate_cmd = Command::new("docker");
        validate_cmd.args(validate_argv(&container_name, &container_staging_path));

        // NAN-2297: bounded because this runs while the shared deploy mutex is
        // held. 60s is generous for a validate — the point is that a wedged
        // docker daemon fails this deploy instead of stalling all of them.
        let output = super::deploy::run_bounded(
            validate_cmd,
            std::time::Duration::from_secs(60),
            "docker exec vector validate",
        )
        .await?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        // Parse the validation output
        let (mut errors, warnings) = Self::parse_validation_output(&stdout, &stderr);

        let combined_output = format!("{}\n{}", stdout, stderr);

        if output.status.success() && errors.is_empty() {
            tracing::info!("Vector configuration validation passed");
            return Ok(ValidationResult {
                success: true,
                errors: vec![],
                warnings,
                raw_output: stdout,
            });
        }

        // NAN-2305: a Docker Desktop bind-mount propagation lag on macOS used to
        // be converted into a PASS here, which promoted the tree unvalidated —
        // and the signature matched genuine config errors too, since every
        // staged path contains "staging" and "Failed to load" is what Vector
        // reports for a file it found and could not parse. It now only adds an
        // explanation to a failure that stays a failure. `SKIP_VECTOR_VALIDATION`
        // remains the explicit way to run without a reachable vector container.
        if looks_like_staging_mount_failure(&combined_output) {
            errors.push(
                "Vector could not load the staged config. If the api container's staging \
                 directory is not visible inside the vector container (a Docker Desktop \
                 bind-mount propagation issue on macOS), fix the mount or set \
                 SKIP_VECTOR_VALIDATION=true deliberately — this deploy is being refused \
                 rather than promoting a config nothing validated."
                    .to_string(),
            );
        }

        let error_msg = if !errors.is_empty() {
            errors.join("; ")
        } else if !stderr.is_empty() {
            stderr.clone()
        } else {
            "Validation failed with unknown error".to_string()
        };

        tracing::warn!("Vector configuration validation failed: {}", error_msg);
        Ok(ValidationResult {
            success: false,
            errors,
            warnings,
            raw_output: combined_output,
        })
    }

    /// Parse Vector validation output to extract errors and warnings
    fn parse_validation_output(stdout: &str, stderr: &str) -> (Vec<String>, Vec<String>) {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        let combined = format!("{}\n{}", stdout, stderr);

        for line in combined.lines() {
            let line_lower = line.to_lowercase();

            // Skip empty lines
            if line.trim().is_empty() {
                continue;
            }

            // Detect errors
            if line_lower.contains("error") || line_lower.contains("failed") {
                errors.push(line.trim().to_string());
            }
            // Detect warnings
            else if line_lower.contains("warn") {
                warnings.push(line.trim().to_string());
            }
            // Also capture lines that look like validation messages
            else if line.contains("Configuration") && line_lower.contains("invalid") {
                errors.push(line.trim().to_string());
            }
        }

        (errors, warnings)
    }

    /// Validate a single parser's config without staging
    /// Useful for quick validation during parser creation/editing
    pub async fn validate_parser_config(
        &self,
        parser: &Parser,
    ) -> Result<ValidationResult, VectorConfigError> {
        // Stage just this parser
        self.cleanup_staging().await?;
        self.stage_parser(parser).await?;

        // Validate
        let result = self.validate_staged_config().await;

        // Cleanup staging regardless of result
        let _ = self.cleanup_staging().await;

        result
    }
}

#[cfg(test)]
mod tests;

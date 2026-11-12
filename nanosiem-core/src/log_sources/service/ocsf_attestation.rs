// SPDX-License-Identifier: AGPL-3.0-or-later

//! OCSF sample validation and the hash-bound publish receipt (NAN-5079).
//!
//! A parser generation (parser VRL plus its enabled extension) that becomes
//! live through publish or deploy on an OCSF deployment must have passed VRL
//! execution followed by [`crate::parsers::validate_ocsf_event`] on at least
//! one representative raw event. The receipt stores only hashes, never
//! sample content, and binds the contract version, so editing either stage
//! or embedding a newer contract invalidates it without cleanup code.
//!
//! Decisions (Dan, 11-08):
//! - D1: sources already live are exempt until their parser changes. A
//!   generation identical to what is live needs no receipt; `deploy_all`,
//!   boot and the publication reconciler never enforce.
//! - D2: a source's FIRST publish may go live without a sample when the
//!   operator explicitly acknowledges it (audited by the caller); the receipt
//!   stays empty, so the next parser change needs a passing sample.
//!
//! Since NAN-5132 publish and deploy run as background jobs; the API runs the
//! gate BEFORE enqueueing ([`LogSourceService::ocsf_publish_precheck`],
//! [`LogSourceService::ocsf_deploy_precheck`]) so a refusal is a 422 on both
//! `wait=true` and `wait=false` and creates no job.

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::helpers::truncate;
use super::{LogSourceService, LogSourceServiceError};
use crate::log_sources::types::{
    LogSource, OcsfAttestationState, OcsfAttestationStatus, ParserTestResult,
};

pub(crate) const OCSF_MAX_SAMPLES: usize = 50;
pub(crate) const OCSF_MAX_SAMPLE_BYTES: usize = 256 * 1024;
pub(crate) const OCSF_MAX_TOTAL_SAMPLE_BYTES: usize = 2 * 1024 * 1024;

/// What the publish/deploy caller supplied for the OCSF gate.
#[derive(Debug, Clone, Default)]
pub struct OcsfGateInput {
    /// Representative raw events; each must pass VRL then OCSF validation.
    pub samples: Vec<String>,
    /// D2: explicit "go live unattested" for a source's first publish.
    pub acknowledge_unattested: bool,
}

/// What the pre-enqueue OCSF check passed (NAN-5079 x NAN-5132).
#[derive(Debug, Clone)]
pub struct OcsfPrecheck {
    pub outcome: OcsfGateOutcome,
    /// Working-copy revision the gate checked (publish pins to it).
    pub revision: chrono::DateTime<chrono::Utc>,
    /// Fingerprint of the generation the gate checked.
    pub parser_sha256: String,
}

/// How the gate let a generation through (the caller audits `Unattested`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcsfGateOutcome {
    /// Not an OCSF deployment, not a log source, or the generation is
    /// already live (D1).
    NotRequired,
    /// An existing receipt matches this generation.
    Reused,
    /// Samples passed and a new receipt was written.
    Attested { samples: usize },
    /// D2: first publish acknowledged without a sample.
    Unattested,
}

fn hash_part(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

/// Fingerprint of a parser generation: contract version, parser VRL, the
/// extension-enabled flag and (when enabled) the extension VRL.
pub(crate) fn ocsf_parser_sha256(
    schema_version: &str,
    parser_vrl: &str,
    extension_enabled: bool,
    extension_vrl: Option<&str>,
) -> String {
    let mut digest = Sha256::new();
    hash_part(&mut digest, b"nano.log-source.ocsf-parser-attestation.v1");
    hash_part(&mut digest, schema_version.as_bytes());
    hash_part(&mut digest, parser_vrl.as_bytes());
    hash_part(&mut digest, &[u8::from(extension_enabled)]);
    if extension_enabled {
        hash_part(&mut digest, extension_vrl.unwrap_or("").as_bytes());
    }
    hex::encode(digest.finalize())
}

fn source_parser_sha256(log_source: &LogSource) -> String {
    ocsf_parser_sha256(
        crate::parsers::ocsf_validation_version(),
        &log_source.parser_vrl,
        log_source.extension_enabled,
        log_source.extension_vrl.as_deref(),
    )
}

/// Framed, order-sensitive receipt over the validated raw samples.
pub(crate) fn ocsf_samples_sha256(samples: &[String]) -> String {
    let mut digest = Sha256::new();
    hash_part(&mut digest, b"nano.log-source.ocsf-samples.v1");
    for sample in samples {
        hash_part(&mut digest, sample.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn effective_extension(log_source: &LogSource) -> Option<&str> {
    log_source
        .extension_enabled
        .then_some(log_source.extension_vrl.as_deref())
        .flatten()
        .filter(|value| !value.trim().is_empty())
}

/// Apply the OCSF contract to one VRL result, only after VRL succeeded.
pub(crate) fn apply_ocsf_validation(mut result: ParserTestResult) -> ParserTestResult {
    if !result.success {
        return result;
    }
    let Some(output) = result.output.as_ref() else {
        return result;
    };
    let validation = crate::parsers::validate_ocsf_event(output);
    if !validation.valid {
        let summary = validation
            .errors
            .iter()
            .take(5)
            .map(|error| format!("{}: {}", error.attribute_path, error.message))
            .collect::<Vec<_>>()
            .join("; ");
        result.success = false;
        result.error = Some(format!("OCSF validation failed: {summary}"));
    }
    result.schema_validation = Some(validation);
    result
}

pub(crate) fn attestation_status(
    receipt: Option<(String, String, i32, chrono::DateTime<chrono::Utc>)>,
    schema_version: &str,
    parser_sha256: &str,
) -> OcsfAttestationStatus {
    match receipt {
        None => OcsfAttestationStatus {
            status: OcsfAttestationState::None,
            schema_version: None,
            sample_count: None,
            validated_at: None,
        },
        Some((version, parser, count, at)) => OcsfAttestationStatus {
            status: if version == schema_version && parser == parser_sha256 {
                OcsfAttestationState::Current
            } else {
                OcsfAttestationState::Stale
            },
            schema_version: Some(version),
            sample_count: Some(count),
            validated_at: Some(at),
        },
    }
}

fn check_sample_limits(samples: &[String]) -> Result<(), LogSourceServiceError> {
    if samples.len() > OCSF_MAX_SAMPLES {
        return Err(LogSourceServiceError::OcsfValidationFailed(format!(
            "at most {OCSF_MAX_SAMPLES} samples may be validated per publish"
        )));
    }
    let mut total = 0usize;
    for sample in samples {
        if sample.len() > OCSF_MAX_SAMPLE_BYTES {
            return Err(LogSourceServiceError::OcsfValidationFailed(format!(
                "a sample exceeds the {OCSF_MAX_SAMPLE_BYTES} byte limit"
            )));
        }
        total = total.saturating_add(sample.len());
    }
    if total > OCSF_MAX_TOTAL_SAMPLE_BYTES {
        return Err(LogSourceServiceError::OcsfValidationFailed(format!(
            "sample payload exceeds the {OCSF_MAX_TOTAL_SAMPLE_BYTES} byte limit"
        )));
    }
    Ok(())
}

fn is_ocsf_deployment() -> Result<bool, LogSourceServiceError> {
    let profile = crate::schema::active_profile_from_env()
        .map_err(LogSourceServiceError::OcsfValidationFailed)?;
    Ok(profile.id() == crate::schema::SchemaId::Ocsf)
}

/// Run the parser (+ extension) over `samples` with OCSF validation.
/// Results are index-aligned with `samples`. Each stage is compiled ONCE
/// for every sample (a 1k-line OCSF parser costs seconds per compile, so
/// per-sample compiles made a 38-sample bundled set take minutes): the
/// parser runs as one batch, then the extension runs as one batch over
/// the parser outputs, which is the order Vector applies them in.
pub(crate) async fn run_ocsf_samples(
    validator: &crate::parsers::VrlValidator,
    parser_vrl: &str,
    extension_vrl: Option<&str>,
    samples: &[String],
) -> Result<Vec<ParserTestResult>, LogSourceServiceError> {
    let inputs: Vec<String> = samples
        .iter()
        .map(|sample| serde_json::json!({ "message": sample }).to_string())
        .collect();
    let parsed = ocsf_batch(validator, parser_vrl, &inputs).await?;
    let Some(extension) = extension_vrl.filter(|ext| !ext.trim().is_empty()) else {
        return Ok(samples
            .iter()
            .zip(parsed)
            .map(|(sample, result)| {
                apply_ocsf_validation(super::validation::live_parser_result(sample, result))
            })
            .collect());
    };
    // Stage 2 only for samples the parser handled; a parser failure keeps
    // its stage-0 error, as the interactive chain test reports it.
    let mut stage_inputs = Vec::new();
    let mut stage_index = Vec::new();
    for (index, result) in parsed.iter().enumerate() {
        if let (true, Some(output)) = (result.success, result.output.as_ref()) {
            stage_index.push(index);
            stage_inputs.push(output.to_string());
        }
    }
    let mut finals: Vec<crate::parsers::ParserTestResult> = parsed
        .into_iter()
        .map(|mut result| {
            if !result.success {
                result.error = Some(format!(
                    "stage 0: {}",
                    result.error.unwrap_or_else(|| "parser failed".into())
                ));
            }
            result
        })
        .collect();
    if !stage_inputs.is_empty() {
        let extended = ocsf_batch(validator, extension, &stage_inputs).await?;
        for (index, mut result) in stage_index.into_iter().zip(extended) {
            result.input = finals[index].input.clone();
            if !result.success {
                result.error = Some(format!(
                    "stage 1: {}",
                    result.error.unwrap_or_else(|| "extension failed".into())
                ));
            }
            finals[index] = result;
        }
    }
    Ok(samples
        .iter()
        .zip(finals)
        .map(|(sample, result)| {
            apply_ocsf_validation(super::validation::live_parser_result(sample, result))
        })
        .collect())
}

/// One compile of `vrl` over every input (see [`run_ocsf_samples`]).
async fn ocsf_batch(
    validator: &crate::parsers::VrlValidator,
    vrl: &str,
    inputs: &[String],
) -> Result<Vec<crate::parsers::ParserTestResult>, LogSourceServiceError> {
    validator
        .test_vrl_batch(vrl, inputs)
        .await
        .map_err(|error| match error {
            crate::parsers::VrlValidatorError::Busy(message) => {
                LogSourceServiceError::ParserTestBusy(message)
            }
            other => LogSourceServiceError::OcsfValidationFailed(other.to_string()),
        })
}

impl LogSourceService {
    /// Run the parser (+ extension) over `samples` with OCSF validation; see
    /// [`run_ocsf_samples`].
    pub(crate) async fn test_ocsf_samples(
        &self,
        parser_vrl: &str,
        extension_vrl: Option<&str>,
        samples: &[String],
    ) -> Result<Vec<ParserTestResult>, LogSourceServiceError> {
        run_ocsf_samples(&self.vrl_validator, parser_vrl, extension_vrl, samples).await
    }

    /// `POST /api/log-sources/test-vrl` with `validate_ocsf`: one sample,
    /// validated after VRL succeeded. Off an OCSF deployment the flag is a
    /// no-op, so clients may always send it.
    pub async fn test_vrl_chain_ocsf(
        &self,
        parser_vrl: &str,
        extension_vrl: Option<&str>,
        sample_log: &str,
    ) -> Result<ParserTestResult, LogSourceServiceError> {
        let result = self.test_vrl_chain(parser_vrl, extension_vrl, sample_log).await?;
        if !is_ocsf_deployment()? {
            return Ok(result);
        }
        Ok(apply_ocsf_validation(result))
    }

    /// Write a 1-sample receipt after an interactive test passed, but only
    /// when the tested VRL is the STORED generation of `id` (an unsaved
    /// editor buffer is validated but never attested). Returns whether a
    /// receipt was written.
    pub async fn record_ocsf_test_attestation(
        &self,
        id: Uuid,
        parser_vrl: &str,
        extension_vrl: Option<&str>,
        sample: &str,
    ) -> Result<bool, LogSourceServiceError> {
        if !is_ocsf_deployment()? {
            return Ok(false);
        }
        let log_source = self.repository().find_by_id(id).await?;
        if log_source.kind != "log" || log_source.parser_vrl != parser_vrl {
            return Ok(false);
        }
        let tested_extension = extension_vrl.filter(|value| !value.trim().is_empty());
        if effective_extension(&log_source) != tested_extension {
            return Ok(false);
        }
        check_sample_limits(std::slice::from_ref(&sample.to_string()))?;
        match self
            .repository()
            .set_ocsf_validation_attestation(
                id,
                crate::parsers::ocsf_validation_version(),
                &source_parser_sha256(&log_source),
                &ocsf_samples_sha256(&[sample.to_string()]),
                1,
                Some(log_source.updated_at),
            )
            .await
        {
            Ok(_) => Ok(true),
            // Edited since it was read: the tested VRL may no longer be the
            // stored generation, so no receipt (the test result still stands).
            Err(crate::log_sources::LogSourceRepositoryError::StaleVersion(_)) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// The receipt state of `log_source`'s working-copy generation, for the
    /// Log Sources UI. `None` off OCSF or for non-log sources.
    pub(crate) async fn ocsf_attestation_status(
        &self,
        log_source: &LogSource,
    ) -> Result<Option<OcsfAttestationStatus>, LogSourceServiceError> {
        // Informational only: an unreadable profile must not fail the GET.
        if !is_ocsf_deployment().unwrap_or(false) || log_source.kind != "log" {
            return Ok(None);
        }
        let receipt = self
            .repository()
            .ocsf_validation_attestation(log_source.id)
            .await?;
        Ok(Some(attestation_status(
            receipt,
            crate::parsers::ocsf_validation_version(),
            &source_parser_sha256(log_source),
        )))
    }

    /// The raw events a first-party library parser shipped with, matched by
    /// EXACT `parser_vrl` against a validated repository row. Editing the VRL
    /// stops the match, so a hand-modified parser must bring its own sample.
    /// Best effort: any failure returns empty.
    async fn library_parser_samples(&self, log_source: &LogSource) -> Vec<String> {
        if log_source.parser_vrl.trim().is_empty() {
            return Vec::new();
        }
        let rows: Vec<(String,)> = match sqlx::query_as(
            "SELECT raw_content FROM repository_parsers \
             WHERE parser_vrl = $1 AND raw_content IS NOT NULL \
             ORDER BY updated_at DESC LIMIT 4",
        )
        .bind(&log_source.parser_vrl)
        .fetch_all(&self.pool)
        .await
        {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(log_source_id = %log_source.id, %error, "could not look up bundled parser samples");
                return Vec::new();
            }
        };
        for (raw_content,) in rows {
            let Ok(parsed) = crate::parser_repository::parse_parser_yaml(&raw_content) else {
                continue;
            };
            let samples: Vec<String> = parsed
                .samples
                .unwrap_or_default()
                .into_iter()
                .map(|sample| sample.raw)
                .filter(|raw| !raw.trim().is_empty() && raw.len() <= OCSF_MAX_SAMPLE_BYTES)
                .take(OCSF_MAX_SAMPLES)
                .collect();
            if !samples.is_empty() {
                return samples;
            }
        }
        Vec::new()
    }

    /// Publish's OCSF gate, run by the API BEFORE a publish job is enqueued
    /// (NAN-5079 x NAN-5132), so a refused generation answers 422 at once on
    /// both `wait=true` and `wait=false` and no job is created.
    ///
    /// The returned `revision` is the working-copy revision the gate checked;
    /// the caller must publish AT that revision (`expected_updated_at`), so an
    /// edit landing between this check and the job is a 409, never an
    /// unvalidated publish. A working copy whose VRL does not validate skips
    /// the gate: the publish job refuses it with its structured result.
    pub async fn ocsf_publish_precheck(
        &self,
        id: Uuid,
        expected_updated_at: Option<chrono::DateTime<chrono::Utc>>,
        input: &OcsfGateInput,
    ) -> Result<OcsfPrecheck, LogSourceServiceError> {
        let log_source = self.repository().find_by_id(id).await?;
        super::versioning::ensure_unchanged(id, log_source.updated_at, expected_updated_at)?;
        let checked = OcsfPrecheck {
            outcome: OcsfGateOutcome::NotRequired,
            revision: log_source.updated_at,
            parser_sha256: source_parser_sha256(&log_source),
        };
        if !self.validate_vrl(&log_source.parser_vrl).await.valid {
            return Ok(checked);
        }
        if let Some(extension) = effective_extension(&log_source) {
            if !self.validate_vrl(extension).await.valid {
                return Ok(checked);
            }
        }
        let active = self.version_repository().get_active_version(id).await?;
        let live = active.as_ref().map(|version| {
            (
                version.parser_vrl.as_str(),
                version.extension_enabled,
                version.extension_vrl.as_deref(),
            )
        });
        let (outcome, revision) = self.enforce_ocsf_gate(&log_source, live, input).await?;
        // NAN-5297: a new receipt bumped `updated_at`; publish continues at the
        // revision the receipt was written at (the receipt write was itself a
        // CAS against the revision checked above, so nothing slipped in).
        Ok(OcsfPrecheck { outcome, revision, ..checked })
    }

    /// Deploy's OCSF gate, run by the API before a deploy job is enqueued.
    /// It applies only when a source that is not deployed and has no
    /// published version goes live: then the working copy is what Vector
    /// renders (the Add data flow's create + deploy). A source with an active
    /// version renders that version, which already passed the publish gate
    /// (or predates it, D1). Internal redeploys never call this.
    pub async fn ocsf_deploy_precheck(
        &self,
        id: Uuid,
        input: &OcsfGateInput,
    ) -> Result<OcsfPrecheck, LogSourceServiceError> {
        let log_source = self.repository().find_by_id(id).await?;
        let mut checked = OcsfPrecheck {
            outcome: OcsfGateOutcome::NotRequired,
            revision: log_source.updated_at,
            parser_sha256: source_parser_sha256(&log_source),
        };
        if !log_source.deployed
            && self.version_repository().get_active_version(id).await?.is_none()
        {
            let (outcome, revision) = self.enforce_ocsf_gate(&log_source, None, input).await?;
            checked.outcome = outcome;
            checked.revision = revision;
        }
        Ok(checked)
    }

    /// Inside the deploy job: the working copy must still be the generation
    /// the precheck passed. A save in between fails the job with the same
    /// 422 error class the precheck would have returned.
    pub async fn ensure_ocsf_generation_unchanged(
        &self,
        id: Uuid,
        checked: &OcsfPrecheck,
    ) -> Result<(), LogSourceServiceError> {
        if checked.outcome == OcsfGateOutcome::NotRequired {
            return Ok(());
        }
        let log_source = self.repository().find_by_id(id).await?;
        if source_parser_sha256(&log_source) != checked.parser_sha256 {
            return Err(LogSourceServiceError::OcsfValidationFailed(
                "the parser changed after its OCSF check; deploy again to validate the new version"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// The OCSF gate for a generation about to go live.
    ///
    /// `live` is the generation currently live for this source, as
    /// `(parser_vrl, extension_enabled, extension_vrl)`, or `None` when
    /// nothing has been published yet. An identical generation is exempt
    /// (D1). Otherwise: supplied samples win; with none, a matching receipt
    /// passes, then the library parser's bundled samples are tried; a first
    /// publish may be acknowledged as unattested (D2); else it is refused.
    ///
    /// Returns the outcome and the source's revision after the gate: unchanged
    /// unless a new receipt was written, which bumps `updated_at` (NAN-5297).
    pub(crate) async fn enforce_ocsf_gate(
        &self,
        log_source: &LogSource,
        live: Option<(&str, bool, Option<&str>)>,
        input: &OcsfGateInput,
    ) -> Result<(OcsfGateOutcome, chrono::DateTime<chrono::Utc>), LogSourceServiceError> {
        let unchanged = log_source.updated_at;
        if !is_ocsf_deployment()? || log_source.kind != "log" {
            return Ok((OcsfGateOutcome::NotRequired, unchanged));
        }
        let version = crate::parsers::ocsf_validation_version();
        let parser_sha256 = source_parser_sha256(log_source);
        if let Some((parser_vrl, extension_enabled, extension_vrl)) = live {
            if ocsf_parser_sha256(version, parser_vrl, extension_enabled, extension_vrl) == parser_sha256 {
                return Ok((OcsfGateOutcome::NotRequired, unchanged));
            }
        }
        // A Nano Pipe plan routes/filters/masks events that a parser already
        // shaped; its output is not a parser's, so the parser gate does not
        // apply (and the plan is not VRL the sample runner can execute).
        if matches!(crate::parsers::pipe::stored_plan(&log_source.parser_vrl), Ok(Some(_))) {
            return Ok((OcsfGateOutcome::NotRequired, unchanged));
        }
        // D1 for rollback: a generation that was published before (a revert)
        // already went live once; never block going back to it.
        if live.is_some() {
            let history = self
                .version_repository()
                .get_version_history(log_source.id, 200)
                .await?;
            if history.iter().any(|v| {
                ocsf_parser_sha256(
                    version,
                    &v.parser_vrl,
                    v.extension_enabled,
                    v.extension_vrl.as_deref(),
                ) == parser_sha256
            }) {
                return Ok((OcsfGateOutcome::NotRequired, unchanged));
            }
        }

        let bundled;
        let samples: &[String] = if input.samples.is_empty() {
            if self
                .repository()
                .has_ocsf_validation_attestation(log_source.id, version, &parser_sha256)
                .await?
            {
                return Ok((OcsfGateOutcome::Reused, unchanged));
            }
            bundled = self.library_parser_samples(log_source).await;
            if bundled.is_empty() {
                if input.acknowledge_unattested && live.is_none() {
                    return Ok((OcsfGateOutcome::Unattested, unchanged));
                }
                return Err(LogSourceServiceError::OcsfValidationFailed(if live.is_none() {
                    "this parser has no OCSF sample-validation receipt; supply at least one representative raw event, or acknowledge an unattested first publish".to_string()
                } else {
                    "this parser change has no OCSF sample-validation receipt; supply at least one representative raw event".to_string()
                }));
            }
            &bundled
        } else {
            &input.samples
        };

        check_sample_limits(samples)?;
        // Safety before conformance: a program the VRL safety layer would
        // quarantine at render never earns an OCSF receipt.
        crate::parsers::vrl_safety::check_program("parser_vrl", &log_source.parser_vrl)
            .map_err(LogSourceServiceError::OcsfValidationFailed)?;
        if let Some(extension) = effective_extension(log_source) {
            crate::parsers::vrl_safety::check_program("extension_vrl", extension)
                .map_err(LogSourceServiceError::OcsfValidationFailed)?;
        }
        let results = self
            .test_ocsf_samples(&log_source.parser_vrl, effective_extension(log_source), samples)
            .await?;
        for (index, result) in results.iter().enumerate() {
            if !result.success {
                return Err(LogSourceServiceError::OcsfValidationFailed(format!(
                    "sample {} ({}) failed: {}",
                    index + 1,
                    truncate(&samples[index], 80),
                    result.error.as_deref().unwrap_or("unknown validation error")
                )));
            }
        }
        let revision = self
            .repository()
            .set_ocsf_validation_attestation(
                log_source.id,
                version,
                &parser_sha256,
                &ocsf_samples_sha256(samples),
                samples.len() as i32,
                Some(unchanged),
            )
            .await?;
        Ok((OcsfGateOutcome::Attested { samples: samples.len() }, revision))
    }
}

#[cfg(test)]
#[path = "ocsf_attestation_tests.rs"]
mod tests;

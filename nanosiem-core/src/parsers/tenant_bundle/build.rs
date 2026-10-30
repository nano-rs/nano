// SPDX-License-Identifier: AGPL-3.0-or-later

//! The build Job's two nanosiem stages and the files that connect them.
//!
//! ```text
//! /input (ConfigMap, ro)   build.json  tenant-sources.json  base.tar.gz  [current.tar.gz]
//!   │ generate (builder image)
//!   ▼
//! /work                    status  generate-report.json  bundle.tar.gz
//!                          vector.env  [tests/tenant-tests.toml]  [merge.diff]
//!                          [pull-bundle.tar.gz]  [pull-runtime-sample.toml]
//!   │ vector-check (the pinned runtimeImageDigest Vector image; /work read-only)
//!   ▼
//! /results                 egress.txt  sa-token.txt  version.txt  validate.{rc,ms,out}
//!                          test.{rc,ms,out}  [pull-validate.{rc,ms,out}]  | skipped
//!   │ finalize (builder image)
//!   ▼
//! /out                     report.json  summary.json  [bundle.tar.gz]  [merge.diff]
//!                          [pull-bundle.tar.gz]
//!                          + the same files framed on stdout, + the termination message
//! ```
//!
//! `generate` never fails on bad tenant input: it records the failure in the
//! report and leaves `status = failed`, and the Vector stage skips. Only
//! infrastructure errors (unreadable mounts) exit non-zero.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::LazyLock;
use std::time::Instant;

use base64::Engine as _;
use regex::Regex;
use sha2::{Digest, Sha256};

use super::archive::{self, BundleTree};
use super::diff;
use super::model::*;
use super::overlay::{self, GeneratedSource};
use super::pull;
use super::vector_tests;
use super::TenantBundleError;

pub const BUILD_FILE: &str = "build.json";
pub const SOURCES_FILE: &str = "tenant-sources.json";
pub const BASE_FILE: &str = "base.tar.gz";
pub const CURRENT_FILE: &str = "current.tar.gz";

pub const STATUS_FILE: &str = "status";
pub const GENERATE_REPORT_FILE: &str = "generate-report.json";
pub const BUNDLE_FILE: &str = "bundle.tar.gz";
pub const ENV_FILE: &str = "vector.env";
pub const TESTS_FILE: &str = "tests/tenant-tests.toml";
pub const MERGE_DIFF_FILE: &str = "merge.diff";
/// NAN-3369: the lanes-subset pull bundle, when the request names pull sources.
pub const PULL_BUNDLE_FILE: &str = "pull-bundle.tar.gz";
/// NAN-3712: with a runtime-config pull bundle, one sample runtime source per
/// template variant ([`pull::render_runtime_sample`]); the Vector stage loads
/// it as `dynamic/pull/pull-runtime-sources.toml` beside the pull bundle.
pub const PULL_RUNTIME_SAMPLE_FILE: &str = "pull-runtime-sample.toml";

pub const REPORT_FILE: &str = "report.json";
pub const SUMMARY_FILE: &str = "summary.json";

/// stdout framing the orchestrator reassembles from the finalize container's
/// log. Each line stays under the kubelet's 16 KiB line split.
pub const LOG_FILE_PREFIX: &str = "NANO_PARSER_BUNDLE_BUILD_FILE ";
pub const LOG_RESULT_PREFIX: &str = "NANO_PARSER_BUNDLE_BUILD_RESULT ";
const LOG_CHUNK_CHARS: usize = 12_000;

/// The placeholder every credential-shaped variable gets. The sandbox holds
/// no secrets; Vector only needs the interpolation to resolve.
pub const PLACEHOLDER: &str = "unused-parser-bundle-build-placeholder";
const PLACEHOLDER_URL: &str = "http://127.0.0.1:9";
const OUTPUT_TAIL_BYTES: usize = 16 * 1024;
const MERGE_DIFF_LIMIT: usize = 1024 * 1024;

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn io_err(path: &Path, e: std::io::Error) -> TenantBundleError {
    TenantBundleError::Io(format!("{}: {e}", path.display()))
}

fn read(path: &Path) -> Result<Vec<u8>, TenantBundleError> {
    std::fs::read(path).map_err(|e| io_err(path, e))
}

fn write(path: &Path, data: impl AsRef<[u8]>) -> Result<(), TenantBundleError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
    }
    std::fs::write(path, data).map_err(|e| io_err(path, e))
}

fn builder_version() -> String {
    format!("nano-parser-bundle-build {}", env!("CARGO_PKG_VERSION"))
}

// ---------------------------------------------------------------------------
// Placeholder environment
// ---------------------------------------------------------------------------

static INTERPOLATION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)((?::?-|:?\?)[^}]*)?\}|\$([A-Za-z_][A-Za-z0-9_]*)")
        .expect("static regex")
});

/// Variables the bundle interpolates without a `:-default`, each with a
/// placeholder. `$$` escapes (every tenant `$`) are not variables.
pub fn placeholder_env(tree: &BundleTree) -> Vec<(String, String)> {
    let mut names = BTreeSet::from(["VECTOR_AUTH_TOKEN".to_string()]);
    for (path, data) in &tree.files {
        if !path.ends_with(".toml") {
            continue;
        }
        let text = String::from_utf8_lossy(data).replace("$$", "");
        for captures in INTERPOLATION_RE.captures_iter(&text) {
            if let Some(name) = captures.get(1) {
                let has_default = captures.get(2).is_some_and(|modifier| {
                    modifier.as_str().trim_start_matches(':').starts_with('-')
                });
                if !has_default {
                    names.insert(name.as_str().to_string());
                }
            } else if let Some(name) = captures.get(3) {
                names.insert(name.as_str().to_string());
            }
        }
    }
    names
        .into_iter()
        .map(|name| {
            let value = if name.ends_with("_URL") || name.ends_with("_ENDPOINT") {
                PLACEHOLDER_URL
            } else {
                PLACEHOLDER
            };
            (name, value.to_string())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// generate
// ---------------------------------------------------------------------------

/// The raw inputs, as mounted.
pub struct BuildInputs {
    pub build_json: Vec<u8>,
    pub sources_json: Vec<u8>,
    pub base: Vec<u8>,
    pub current: Option<Vec<u8>>,
}

impl BuildInputs {
    pub fn read(dir: &Path) -> Result<Self, TenantBundleError> {
        let current_path = dir.join(CURRENT_FILE);
        Ok(Self {
            build_json: read(&dir.join(BUILD_FILE))?,
            sources_json: read(&dir.join(SOURCES_FILE))?,
            base: read(&dir.join(BASE_FILE))?,
            current: current_path
                .exists()
                .then(|| read(&current_path))
                .transpose()?,
        })
    }
}

/// What `generate` hands the later stages.
pub struct GenerateOutcome {
    pub report: BuildReport,
    pub bundle: Option<Vec<u8>>,
    pub tests_toml: Option<String>,
    pub source_test_configs: Vec<String>,
    pub env: Vec<(String, String)>,
    pub merge_diff: Option<String>,
    pub pull_bundle: Option<Vec<u8>>,
    /// NAN-3712: [`PULL_RUNTIME_SAMPLE_FILE`], with a runtime pull bundle.
    pub pull_runtime_sample: Option<String>,
}

impl GenerateOutcome {
    pub fn ok(&self) -> bool {
        self.report.failure.is_none()
    }
}

fn check(name: &str, status: CheckStatus, findings: Vec<GuardFinding>) -> Check {
    Check {
        name: name.into(),
        status,
        duration_ms: None,
        findings,
        tests: Vec::new(),
        output: None,
        exit_code: None,
        exception: None,
    }
}

/// Record a build failure. The first failure wins: a later stage (the sandbox
/// probe, a missing Vector result, ...) never replaces the failure that actually
/// stopped the build, so the report always names the root cause (NAN-2969).
fn fail(report: &mut BuildReport, stage: Stage, source: Option<String>, message: String) {
    fail_at(report, stage, source, None, message);
}

/// [`fail`] with the Vector component the failure is attributed to.
fn fail_at(
    report: &mut BuildReport,
    stage: Stage,
    source: Option<String>,
    component: Option<String>,
    message: String,
) {
    report.verdict = Verdict::Failed;
    if report.failure.is_none() {
        report.failure = Some(Failure {
            stage,
            source,
            component,
            message,
        });
    }
}

/// Artifacts a successful `generate` hands the later stages.
struct Artifacts {
    bundle: Vec<u8>,
    tests_toml: Option<String>,
    source_test_configs: Vec<String>,
    env: Vec<(String, String)>,
    merge_diff: Option<String>,
    pull_bundle: Option<Vec<u8>>,
    pull_runtime_sample: Option<String>,
}

/// The pure part of the `generate` stage.
pub fn generate(inputs: &BuildInputs) -> GenerateOutcome {
    let started = Instant::now();
    let parsed = serde_json::from_slice::<BuildRequest>(&inputs.build_json)
        .map_err(|e| TenantBundleError::Input(format!("build.json: {e}")));
    let request = parsed.as_ref().ok();
    let mut report = BuildReport {
        schema_version: BUILD_SCHEMA_VERSION,
        kind: REPORT_KIND.into(),
        build_id: request.map(|r| r.build_id.clone()).unwrap_or_default(),
        tenant_id: request.map(|r| r.tenant_id.clone()).unwrap_or_default(),
        tenant_uuid: request.map(|r| r.tenant_uuid).unwrap_or_default(),
        purpose: request.map(|r| r.purpose).unwrap_or(BuildPurpose::Rollout),
        verdict: Verdict::Passed,
        failure: None,
        inputs: InputDigests {
            build_sha256: sha256_hex(&inputs.build_json),
            build_request_sha256: request.map(build_request_sha256),
            tenant_sources_sha256: sha256_hex(&inputs.sources_json),
            base_sha256: sha256_hex(&inputs.base),
            current_sha256: inputs.current.as_deref().map(sha256_hex),
        },
        versions: Versions {
            builder: builder_version(),
            runtime_image_digest: request
                .map(|r| r.runtime_image_digest.clone())
                .unwrap_or_default(),
            vector: None,
        },
        bundle: None,
        sources: Vec::new(),
        checks: Vec::new(),
        timings_ms: Timings::default(),
        merge: None,
        pull_bundle: None,
        pull_pending: Vec::new(),
        pull_pending_lanes: Vec::new(),
        report_sha256: None,
    };
    let artifacts = match &parsed {
        Ok(request) => generate_into(inputs, request, &mut report),
        Err(e) => {
            fail(&mut report, Stage::Inputs, None, e.to_string());
            None
        }
    };
    report.timings_ms.generate_ms = started.elapsed().as_millis() as u64;
    match artifacts {
        Some(a) => GenerateOutcome {
            report,
            bundle: Some(a.bundle),
            tests_toml: a.tests_toml,
            source_test_configs: a.source_test_configs,
            env: a.env,
            merge_diff: a.merge_diff,
            pull_bundle: a.pull_bundle,
            pull_runtime_sample: a.pull_runtime_sample,
        },
        None => {
            report.bundle = None;
            report.merge = None;
            report.pull_bundle = None;
            GenerateOutcome {
                report,
                bundle: None,
                tests_toml: None,
                source_test_configs: Vec::new(),
                env: Vec::new(),
                merge_diff: None,
                pull_bundle: None,
                pull_runtime_sample: None,
            }
        }
    }
}

fn input_error(report: &mut BuildReport, message: String) -> Option<Artifacts> {
    fail(report, Stage::Inputs, None, message);
    None
}

/// Run every generate step; on failure record it in `report` and return `None`.
fn generate_into(
    inputs: &BuildInputs,
    request: &BuildRequest,
    report: &mut BuildReport,
) -> Option<Artifacts> {
    if let Err(e) = request.validate() {
        return input_error(report, e.to_string());
    }
    let sources = match serde_json::from_slice::<TenantSources>(&inputs.sources_json)
        .map_err(|e| TenantBundleError::Input(format!("tenant-sources.json: {e}")))
        .and_then(|s| s.validate(&request.tenant_id).map(|_| s))
    {
        Ok(sources) => sources,
        Err(e) => return input_error(report, e.to_string()),
    };
    if report.inputs.base_sha256 != request.base_sha256 {
        return input_error(report, "base.tar.gz does not match base_sha256".into());
    }
    if report.inputs.current_sha256 != request.current_sha256 {
        return input_error(
            report,
            "current.tar.gz does not match current_sha256 (or is missing/unexpected)".into(),
        );
    }
    let base = match archive::unpack(&inputs.base) {
        Ok(tree) => tree,
        Err(e) => return input_error(report, format!("platform base: {e}")),
    };

    // -- overlay -----------------------------------------------------------
    let (candidate, generated) = match overlay::apply_overlay(&base, &sources.sources) {
        Ok(result) => result,
        Err(TenantBundleError::Overlay { slug, message }) => {
            fail(report, Stage::Overlay, slug, message);
            return None;
        }
        Err(other) => {
            fail(report, Stage::Overlay, None, other.to_string());
            return None;
        }
    };
    let changed: Option<BTreeSet<&str>> = request
        .changed_sources
        .as_ref()
        .map(|list| list.iter().map(String::as_str).collect());
    let is_changed = |slug: &str| changed.as_ref().is_none_or(|set| set.contains(slug));
    let by_slug = |slug: &str| sources.sources.iter().find(|s| s.slug == slug);
    report.sources = generated
        .iter()
        .filter_map(|g| {
            let source = by_slug(&g.tenant.slug)?;
            Some(SourceReport {
                slug: g.tenant.slug.clone(),
                log_source_id: source.log_source_id,
                version_id: source.version_id,
                version_number: source.version_number,
                file: g.tenant.file(),
                components: g.components.clone(),
                changed: is_changed(&g.tenant.slug),
                samples: source.samples.len(),
                forked_from: source.forked_from.clone(),
            })
        })
        .collect();

    for source in sources.sources.iter().filter(|source| source.parser_vrl.trim().is_empty()
        && !(source.extension_enabled && source.extension_vrl.as_deref().is_some_and(|v| !v.trim().is_empty()))) {
        report.sources.push(SourceReport {
            slug: source.slug.clone(), log_source_id: source.log_source_id,
            version_id: source.version_id, version_number: source.version_number,
            file: overlay::UNPARSED_SOURCES_FILE.into(), components: Vec::new(),
            changed: is_changed(&source.slug), samples: source.samples.len(), forked_from: None,
        });
    }
    report.sources.sort_by(|a, b| a.slug.cmp(&b.slug));

    // -- structural guard ---------------------------------------------------
    let guard_started = Instant::now();
    let verified = overlay::verify_against_base(&base, &candidate);
    let guard_ms = Some(guard_started.elapsed().as_millis() as u64);
    let verified = match verified {
        Ok(verified) => {
            let mut c = check("structural_guard", CheckStatus::Passed, Vec::new());
            c.duration_ms = guard_ms;
            report.checks.push(c);
            verified
        }
        Err(findings) => {
            let first = findings.first().cloned();
            let mut c = check("structural_guard", CheckStatus::Failed, findings);
            c.duration_ms = guard_ms;
            report.checks.push(c);
            let (source, message) = first
                .map(|f| {
                    let message = match f.path {
                        Some(path) => format!("{path}: {}", f.message),
                        None => f.message,
                    };
                    (f.source, message)
                })
                .unwrap_or_default();
            fail(report, Stage::StructuralGuard, source, message);
            return None;
        }
    };
    if request.require_samples {
        if let Some(missing) = report.sources.iter().find(|s| s.changed && !s.components.is_empty() && s.samples == 0) {
            let slug = missing.slug.clone();
            fail(
                report,
                Stage::VectorTest,
                Some(slug.clone()),
                format!("{slug} has no saved samples to test"),
            );
            return None;
        }
    }

    // -- package --------------------------------------------------------------
    let package_started = Instant::now();
    let packed = match archive::pack(&candidate) {
        Ok(packed) => packed,
        Err(e) => {
            fail(report, Stage::Package, None, e.to_string());
            return None;
        }
    };
    report.timings_ms.package_ms = package_started.elapsed().as_millis() as u64;
    let content_sha256 = sha256_hex(&packed);
    report.bundle = Some(BundleOutput {
        object_key: format!(
            "tenants/{}/parser-bundles/{content_sha256}.tar.gz",
            request.tenant_uuid
        ),
        content_sha256,
        gzip_bytes: packed.len() as u64,
        hec_sources: verified.hec_sources.clone(),
        hec_config_sha256: verified.hec_config_sha256.clone(),
        output_guard_sha256: verified.output_guard_sha256.clone(),
        tenant_sources: verified.tenants.iter().map(|t| t.slug.clone()).chain(verified.unparsed_sources.iter().cloned()).collect::<BTreeSet<_>>().into_iter().collect(),
    });

    // -- vector test cases ------------------------------------------------------
    let cases: Vec<(&GeneratedSource, &[String])> = generated
        .iter()
        .filter(|g| is_changed(&g.tenant.slug))
        .filter_map(|g| by_slug(&g.tenant.slug).map(|s| (g, s.samples.as_slice())))
        .collect();
    let tests_toml = vector_tests::render(&cases);
    let source_test_configs = match vector_tests::source_configs(&candidate, &cases) {
        Ok(configs) => configs,
        Err(e) => return input_error(report, e.to_string()),
    };

    // -- pull bundle (NAN-3369) ---------------------------------------------------
    let mut pull_packed = None;
    let mut pull_runtime_sample = None;
    let mut env_trees = vec![&candidate];
    let pull_build;
    let mut built = None;
    if let Some(requested) = &request.pull_sources {
        let (rendered, pending) = pull::plan(&sources.sources, requested);
        report.pull_pending = pending;
        if !rendered.is_empty() {
            built = Some((
                pull::build_pull_bundle_with(
                    &base,
                    &sources.sources,
                    &rendered,
                    request.tenant_uuid,
                    request.pull_capture,
                    // NAN-3653: every pull bundle this builder emits carries the
                    // origin stamp; the report says so (`PullBundleOutput::pull_origin`).
                    true,
                ),
                false,
            ));
        }
    } else if let Some(requested) = &request.pull_lanes {
        // NAN-3712: the runtime-config pull bundle (code only).
        let (lanes, pending) = pull::plan_lanes(&sources.sources, requested);
        report.pull_pending_lanes = pending;
        if !lanes.is_empty() {
            built = Some((
                pull::build_pull_runtime_bundle(
                    &base,
                    &sources.sources,
                    &lanes,
                    request.pull_capture,
                ),
                true,
            ));
        }
    }
    if let Some((result, runtime)) = built {
        pull_build = match build_pull(&candidate, result, runtime, request, report) {
            Some(built) => built,
            None => return None,
        };
        env_trees.push(&pull_build.0.candidate);
        pull_packed = Some(pull_build.1.clone());
        if runtime {
            pull_runtime_sample = Some(pull::render_runtime_sample(request.tenant_uuid));
        }
    }
    let env = placeholder_env_all(&env_trees);

    // -- merge candidate --------------------------------------------------------
    let mut merge_diff = None;
    if request.purpose == BuildPurpose::MergeCandidate {
        match merge_report(&base, &candidate, inputs, &sources, request) {
            Ok((merge, text)) => {
                report.merge = Some(merge);
                merge_diff = Some(text);
            }
            Err(e) => return input_error(report, e.to_string()),
        }
    }
    Some(Artifacts {
        bundle: packed,
        tests_toml,
        source_test_configs,
        env,
        merge_diff,
        pull_bundle: pull_packed,
        pull_runtime_sample,
    })
}

/// Build, verify and pack the pull bundle; record it in `report`. On failure
/// the whole build fails (one verdict, one report digest): a pull lane is the
/// same lane as in the full bundle, so a pull failure is a platform defect.
/// `runtime` (NAN-3712): `built` is a runtime-config pull bundle.
fn build_pull(
    full: &BundleTree,
    built: Result<pull::PullBuild, TenantBundleError>,
    runtime: bool,
    request: &BuildRequest,
    report: &mut BuildReport,
) -> Option<(pull::PullBuild, Vec<u8>)> {
    let built = match built {
        Ok(built) => built,
        Err(TenantBundleError::Overlay { slug, message }) => {
            fail(
                report,
                Stage::Overlay,
                slug,
                format!("pull bundle: {message}"),
            );
            return None;
        }
        Err(other) => {
            fail(report, Stage::Overlay, None, other.to_string());
            return None;
        }
    };
    let started = Instant::now();
    let verified = overlay::verify_against_base_with(
        &built.base,
        &built.candidate,
        overlay::OverlayProfile::Pull,
    );
    let mut findings = match verified {
        Ok(verified) => {
            let lanes: Vec<&str> = verified.tenants.iter().map(|t| t.slug.as_str()).collect();
            if lanes != built.lane_sources {
                vec![GuardFinding {
                    path: None,
                    source: None,
                    rule: "lane_filter".into(),
                    message: "the pull bundle's lanes differ from the lane filter".into(),
                }]
            } else {
                Vec::new()
            }
        }
        Err(findings) => findings,
    };
    // The pull lanes ARE the full bundle's lanes, byte for byte.
    for (path, data) in &built.candidate.files {
        if path.contains(overlay::TENANT_PREFIX) && full.file(path) != Some(data.as_slice()) {
            findings.push(GuardFinding {
                path: Some(path.clone()),
                source: None,
                rule: "lane_identical".into(),
                message: "pull lane differs from the tenant bundle's lane".into(),
            });
        }
    }
    let mut c = check(
        "pull_structural_guard",
        if findings.is_empty() {
            CheckStatus::Passed
        } else {
            CheckStatus::Failed
        },
        findings.clone(),
    );
    c.duration_ms = Some(started.elapsed().as_millis() as u64);
    report.checks.push(c);
    if let Some(first) = findings.first() {
        let message = match &first.path {
            Some(path) => format!("pull bundle: {path}: {}", first.message),
            None => format!("pull bundle: {}", first.message),
        };
        fail(
            report,
            Stage::StructuralGuard,
            first.source.clone(),
            message,
        );
        return None;
    }
    let packed = match archive::pack(&built.candidate) {
        Ok(packed) => packed,
        Err(e) => {
            fail(report, Stage::Package, None, format!("pull bundle: {e}"));
            return None;
        }
    };
    let base_packed = match archive::pack(&built.base) {
        Ok(packed) => packed,
        Err(e) => {
            fail(report, Stage::Package, None, format!("pull base: {e}"));
            return None;
        }
    };
    let pull_bundle_sha256 = sha256_hex(&packed);
    report.pull_bundle = Some(PullBundleOutput {
        object_key: format!(
            "tenants/{}/pull-bundles/{pull_bundle_sha256}.tar.gz",
            request.tenant_uuid
        ),
        pull_bundle_sha256,
        gzip_bytes: packed.len() as u64,
        base_sha256: sha256_hex(&base_packed),
        lane_sources: built.lane_sources.clone(),
        pull_sources: built.pull_sources.clone(),
        pull_origin: true,
        pull_runtime_contract: runtime.then(|| pull::PULL_RUNTIME_CONTRACT.to_string()),
    });
    Some((built, packed))
}

/// [`placeholder_env`] over several trees, deduplicated.
fn placeholder_env_all(trees: &[&BundleTree]) -> Vec<(String, String)> {
    let merged: std::collections::BTreeMap<String, String> = trees
        .iter()
        .flat_map(|tree| placeholder_env(tree))
        .collect();
    merged.into_iter().collect()
}

/// Decision (a): diff the tenant's current bundle against the candidate built
/// on the new base, and say which platform files and forked parsers changed.
fn merge_report(
    new_base: &BundleTree,
    candidate: &BundleTree,
    inputs: &BuildInputs,
    sources: &TenantSources,
    request: &BuildRequest,
) -> Result<(MergeReport, String), TenantBundleError> {
    let current_bytes = inputs
        .current
        .as_deref()
        .ok_or_else(|| TenantBundleError::Input("merge_candidate without current.tar.gz".into()))?;
    let current = archive::unpack(current_bytes)
        .map_err(|e| TenantBundleError::Input(format!("current bundle: {e}")))?;
    let (current_platform, _) = overlay::strip_overlay(&current).map_err(|findings| {
        TenantBundleError::Input(format!(
            "current bundle is not platform + overlay: {}",
            findings
                .first()
                .map(|f| f.message.clone())
                .unwrap_or_default()
        ))
    })?;
    let platform_files_changed = diff::changed_paths(&current_platform, new_base);
    let (candidate_platform, _) = overlay::strip_overlay(candidate)
        .map_err(|_| TenantBundleError::Input("candidate failed to strip".into()))?;
    let overlay_files_changed: Vec<String> = diff::changed_paths(&current, candidate)
        .into_iter()
        .filter(|path| {
            // A path whose change is not explained by the platform moving.
            current_platform.files.get(path) == candidate_platform.files.get(path)
                || path.contains(overlay::TENANT_PREFIX)
        })
        .collect();
    let mut fork_upstream = Vec::new();
    for source in &sources.sources {
        let Some(forked_from) = &source.forked_from else {
            continue;
        };
        let old_file = overlay::platform_parser_file(&current_platform, forked_from);
        let new_file = overlay::platform_parser_file(new_base, forked_from);
        let upstream_changed = match (&old_file, &new_file) {
            (Some(old), Some(new)) => current_platform.file(old) != new_base.file(new),
            (None, None) => false,
            _ => true,
        };
        fork_upstream.push(ForkUpstream {
            slug: source.slug.clone(),
            forked_from: forked_from.clone(),
            platform_file: new_file,
            upstream_changed,
        });
    }
    let (text, diff_truncated) = diff::unified(&current, candidate, MERGE_DIFF_LIMIT);
    let merge = MergeReport {
        replaces_current: false,
        current_sha256: request.current_sha256.clone().unwrap_or_default(),
        platform_files_changed,
        overlay_files_changed,
        fork_upstream,
        diff_path: MERGE_DIFF_FILE.into(),
        diff_sha256: sha256_hex(text.as_bytes()),
        diff_truncated,
    };
    Ok((merge, text))
}

/// The `generate` stage: read `/input`, write `/work`.
pub fn run_generate(input: &Path, work: &Path) -> Result<GenerateOutcome, TenantBundleError> {
    let inputs = BuildInputs::read(input)?;
    let outcome = generate(&inputs);
    if let Some(bundle) = &outcome.bundle {
        write(&work.join(BUNDLE_FILE), bundle)?;
    }
    if let Some(tests) = &outcome.tests_toml {
        write(&work.join(TESTS_FILE), tests)?;
    }
    for (index, config) in outcome.source_test_configs.iter().enumerate() {
        write(&work.join(format!("source-tests/{index}.toml")), config)?;
    }
    if let Some(diff) = &outcome.merge_diff {
        write(&work.join(MERGE_DIFF_FILE), diff)?;
    }
    if let Some(pull) = &outcome.pull_bundle {
        write(&work.join(PULL_BUNDLE_FILE), pull)?;
    }
    if let Some(sample) = &outcome.pull_runtime_sample {
        write(&work.join(PULL_RUNTIME_SAMPLE_FILE), sample)?;
    }
    let env: String = outcome
        .env
        .iter()
        .map(|(name, value)| format!("{name}={value}\n"))
        .collect();
    write(&work.join(ENV_FILE), env)?;
    write(
        &work.join(GENERATE_REPORT_FILE),
        serde_json::to_vec(&outcome.report).map_err(|e| TenantBundleError::Io(e.to_string()))?,
    )?;
    // Written last: the Vector stage runs only on a complete `ok` hand-off.
    write(
        &work.join(STATUS_FILE),
        if outcome.ok() { "ok\n" } else { "failed\n" },
    )?;
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// finalize
// ---------------------------------------------------------------------------

/// The Vector stage's raw results.
#[derive(Debug, Default, Clone)]
pub struct VectorResults {
    pub skipped: bool,
    /// The Vector stage's own egress probe: `blocked`, or one
    /// `open:<host>:<port>` line per reachable target.
    pub egress: Option<String>,
    pub version: Option<String>,
    pub validate: Option<ToolRun>,
    pub test: Option<ToolRun>,
    /// NAN-3369: `vector validate` of the pull bundle, in its own cell layout.
    pub pull_validate: Option<ToolRun>,
}

#[derive(Debug, Clone)]
pub struct ToolRun {
    pub exit_code: i32,
    pub duration_ms: u64,
    pub output: String,
}

impl VectorResults {
    pub fn read(dir: &Path) -> Self {
        let text = |name: &str| std::fs::read_to_string(dir.join(name)).ok();
        let run = |stem: &str| -> Option<ToolRun> {
            let exit_code = text(&format!("{stem}.rc"))?.trim().parse().ok()?;
            Some(ToolRun {
                exit_code,
                duration_ms: text(&format!("{stem}.ms"))
                    .and_then(|ms| ms.trim().parse().ok())
                    .unwrap_or(0),
                output: text(&format!("{stem}.out")).unwrap_or_default(),
            })
        };
        Self {
            skipped: dir.join("skipped").exists(),
            egress: text("egress.txt").map(|v| v.trim().to_string()),
            version: text("version.txt").map(|v| v.trim().to_string()),
            validate: run("validate"),
            test: run("test"),
            pull_validate: run("pull-validate"),
        }
    }
}

static VECTOR_VERSION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^vector [0-9]+\.[0-9]+\.[0-9]+(?:\s|$)").expect("static regex"));
static ANSI_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\x1b\[[0-9;]*[A-Za-z]").expect("static regex"));
static TENANT_COMPONENT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"tenant__[a-z0-9_]+").expect("static regex"));
static TEST_LINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^test (.+?) \.\.\. (passed|failed)\s*$").expect("static regex")
});

fn tail(text: &str) -> String {
    let clean = ANSI_RE.replace_all(text, "");
    if clean.len() <= OUTPUT_TAIL_BYTES {
        return clean.into_owned();
    }
    let mut start = clean.len() - OUTPUT_TAIL_BYTES;
    while !clean.is_char_boundary(start) {
        start += 1;
    }
    format!("…{}", &clean[start..])
}

/// The part of Vector's output an analyst needs: from the first error line
/// (`x Transform "…": …` or `error…`) on, without the load warnings.
fn vector_error_excerpt(output: &str) -> String {
    let clean = ANSI_RE.replace_all(output, "");
    let start = clean
        .match_indices('\n')
        .map(|(index, _)| index + 1)
        .chain(std::iter::once(0))
        .filter(|&index| {
            let line = &clean[index..];
            line.starts_with("x ") || line.starts_with("error") || line.starts_with("failures:")
        })
        .min();
    tail(start.map_or(&clean[..], |index| &clean[index..]).trim_end())
}

/// Attribute Vector's error text to the first tenant component it names.
fn attribute(report: &BuildReport, output: &str) -> (Option<String>, Option<String>) {
    let mut best: Option<(&str, &str)> = None;
    for found in TENANT_COMPONENT_RE.find_iter(output) {
        let name = found.as_str();
        if let Some(source) = report.sources.iter().find(|s| {
            s.components
                .iter()
                .any(|c| c == name || name.starts_with(c.as_str()))
        }) {
            best = Some((source.slug.as_str(), name));
            break;
        }
    }
    match best {
        Some((slug, component)) => (Some(slug.to_string()), Some(component.to_string())),
        None => (None, None),
    }
}

// ---------------------------------------------------------------------------
// sandbox egress (NAN-2987)
// ---------------------------------------------------------------------------
//
// Why one target is tolerated. On the lake cluster (Rackspace Spot, Calico)
// the build pod can open a TCP connection to the in-cluster Kubernetes API
// ($KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT, 10.21.0.40:443 there)
// despite the namespace deny-all NetworkPolicy: Calico's
// `DefaultEndpointToHostAction=ACCEPT` (the Tigera default) lets
// workload→host traffic through, and that API endpoint is node-local, so no
// NetworkPolicy covers it. Pod security stays `restricted` and the pod gets
// no NET_ADMIN, so it cannot firewall itself.
//
// Reachability is not access: the pod mounts no service-account token
// (`automountServiceAccountToken: false`), the ServiceAccount has no RBAC,
// and an anonymous caller sees only public info (/version, /healthz). So the
// check passes with the named exception `k8s_api_unauthenticated` only when
// ALL hold, and fails otherwise:
//   (a) the Kubernetes API is the ONLY reachable egress target;
//   (b) no service-account token is mounted (checked by the Vector stage AND
//       by finalize, at the fixed kubelet path);
//   (c) anonymous `GET https://<api>/api` answers 401 or 403. /version and
//       /healthz may be public and are not probed.
// The exception is always recorded in the report (status `passed`,
// `exception`, `output: open:<host>:<port>`), never reported as `blocked`.

/// Where the kubelet mounts a service-account token.
pub const SERVICE_ACCOUNT_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
/// The Vector stage's token probe: `absent` or `present`.
pub const SA_TOKEN_FILE: &str = "sa-token.txt";

/// What finalize knows about the sandbox besides the Vector stage's egress
/// probe. [`SandboxProbe::default`] tolerates nothing: any open target fails.
#[derive(Debug, Default, Clone)]
pub struct SandboxProbe {
    /// `<host>:<port>` of the in-cluster API, from finalize's own
    /// `KUBERNETES_SERVICE_HOST`/`KUBERNETES_SERVICE_PORT`.
    pub k8s_api: Option<String>,
    /// The Vector stage's token probe (`sa-token.txt`): `None` = not recorded.
    pub stage_token_present: Option<bool>,
    /// A token is mounted in the finalize container.
    pub finalize_token_present: bool,
    /// Anonymous `GET /api`: the HTTP status, or why there was none.
    pub anonymous_api: Option<Result<u16, String>>,
}

impl SandboxProbe {
    /// The in-cluster API target from an environment lookup, formatted the
    /// way `vector-check.sh` writes it (`open:<host>:<port>`, port default 443).
    pub fn k8s_api_target(env: impl Fn(&str) -> Option<String>) -> Option<String> {
        let host = env("KUBERNETES_SERVICE_HOST").filter(|h| !h.trim().is_empty())?;
        let port = env("KUBERNETES_SERVICE_PORT")
            .filter(|p| !p.trim().is_empty())
            .unwrap_or_else(|| "443".into());
        Some(format!("{}:{}", host.trim(), port.trim()))
    }

    /// Gather the probe inside the finalize container: its env, its own token
    /// mount, the Vector stage's `sa-token.txt`, and — only when the Kubernetes
    /// API is the sole open target — the anonymous `/api` request via `get`.
    pub fn gather(
        results_dir: &Path,
        egress: Option<&str>,
        env: impl Fn(&str) -> Option<String>,
        finalize_token_present: bool,
        get: impl FnOnce(&str) -> Result<u16, String>,
    ) -> Self {
        let k8s_api = Self::k8s_api_target(env);
        let stage_token_present = std::fs::read_to_string(results_dir.join(SA_TOKEN_FILE))
            .ok()
            .and_then(|v| match v.trim() {
                "absent" => Some(false),
                "present" => Some(true),
                _ => None,
            });
        let only_k8s = match (&k8s_api, egress) {
            (Some(api), Some(egress)) => {
                let open = open_targets(egress);
                open.len() == 1 && open[0] == format!("open:{api}")
            }
            _ => false,
        };
        let anonymous_api = only_k8s.then(|| get(&k8s_api_url(k8s_api.as_deref().unwrap())));
        Self {
            k8s_api,
            stage_token_present,
            finalize_token_present,
            anonymous_api,
        }
    }
}

/// `https://<host>:<port>/api`, bracketing an IPv6 host.
pub fn k8s_api_url(target: &str) -> String {
    let (host, port) = target.rsplit_once(':').unwrap_or((target, "443"));
    if host.contains(':') && !host.starts_with('[') {
        format!("https://[{host}]:{port}/api")
    } else {
        format!("https://{host}:{port}/api")
    }
}

/// The open targets in `egress.txt`: one `open:<host>:<port>` per line.
/// Anything that is not `blocked` counts, so a malformed line fails closed.
fn open_targets(egress: &str) -> Vec<String> {
    egress
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && *l != "blocked")
        .map(str::to_string)
        .collect()
}

/// The `sandbox_egress` check and, when it fails, the build failure message.
fn sandbox_egress_check(egress: Option<&str>, probe: &SandboxProbe) -> (Check, Option<String>) {
    let mut sandbox = check("sandbox_egress", CheckStatus::Skipped, Vec::new());
    let Some(egress) = egress else {
        return (sandbox, None);
    };
    let open = open_targets(egress);
    if open.is_empty() && egress.trim() == "blocked" {
        sandbox.status = CheckStatus::Passed;
        return (sandbox, None);
    }
    let listed = if open.is_empty() {
        egress.trim().to_string()
    } else {
        open.join(", ")
    };
    sandbox.output = Some(listed.clone());
    let k8s = probe.k8s_api.as_ref().map(|api| format!("open:{api}"));
    let only_k8s = k8s.is_some() && open.len() == 1 && Some(&open[0]) == k8s.as_ref();
    let refusal = if !only_k8s {
        // Any target besides the API (or no known API at all): as before.
        Some(format!("the build sandbox has network egress ({listed})"))
    } else if probe.stage_token_present != Some(false) || probe.finalize_token_present {
        let why = match probe.stage_token_present {
            None if !probe.finalize_token_present => "its token mount was not recorded",
            _ => "a service-account token is mounted",
        };
        Some(format!(
            "the build sandbox reaches the Kubernetes API ({listed}) and {why}"
        ))
    } else {
        match &probe.anonymous_api {
            Some(Ok(401 | 403)) => None,
            Some(Ok(status)) => Some(format!(
                "the build sandbox reaches the Kubernetes API ({listed}) and anonymous GET /api returned {status}"
            )),
            Some(Err(error)) => Some(format!(
                "the build sandbox reaches the Kubernetes API ({listed}) and anonymous GET /api could not be verified: {}",
                tail(error)
            )),
            None => Some(format!(
                "the build sandbox reaches the Kubernetes API ({listed}) and anonymous GET /api was not probed"
            )),
        }
    };
    match refusal {
        None => {
            sandbox.status = CheckStatus::Passed;
            sandbox.exception = Some(SANDBOX_EXCEPTION_K8S_API_UNAUTHENTICATED.into());
            (sandbox, None)
        }
        Some(message) => {
            sandbox.status = CheckStatus::Failed;
            (sandbox, Some(message))
        }
    }
}

/// Fold the Vector results into the generate report: the final verdict.
/// Tolerates no sandbox egress at all; see [`finalize_report_with_sandbox`].
pub fn finalize_report(
    report: BuildReport,
    results: &VectorResults,
    bundle: Option<&[u8]>,
    runtime_image_digest: Option<&str>,
) -> BuildReport {
    finalize_report_with_sandbox(
        report,
        results,
        &SandboxProbe::default(),
        bundle,
        runtime_image_digest,
    )
}

/// [`finalize_report`] with the finalize container's sandbox probe, which can
/// admit the one `k8s_api_unauthenticated` exception.
pub fn finalize_report_with_sandbox(
    report: BuildReport,
    results: &VectorResults,
    sandbox_probe: &SandboxProbe,
    bundle: Option<&[u8]>,
    runtime_image_digest: Option<&str>,
) -> BuildReport {
    finalize_report_with_pull(
        report,
        results,
        sandbox_probe,
        bundle,
        None,
        runtime_image_digest,
    )
}

/// [`finalize_report_with_sandbox`] for a build that may carry a pull bundle
/// (NAN-3369): its bytes must still be what `generate` recorded, and its own
/// `vector validate` must have passed.
pub fn finalize_report_with_pull(
    mut report: BuildReport,
    results: &VectorResults,
    sandbox_probe: &SandboxProbe,
    bundle: Option<&[u8]>,
    pull_bundle: Option<&[u8]>,
    runtime_image_digest: Option<&str>,
) -> BuildReport {
    report.versions.vector = results.version.clone();
    if report.failure.is_none() {
        if let Some(digest) = runtime_image_digest {
            if digest != report.versions.runtime_image_digest {
                fail(
                    &mut report,
                    Stage::Inputs,
                    None,
                    "the Job's Vector image digest differs from build.json runtime_image_digest"
                        .into(),
                );
            }
        }
    }
    if report.failure.is_none() {
        let recorded = report.bundle.as_ref().map(|b| b.content_sha256.clone());
        if bundle.map(sha256_hex) != recorded {
            fail(
                &mut report,
                Stage::Package,
                None,
                "bundle.tar.gz changed between generate and finalize".into(),
            );
        }
    }
    if report.failure.is_none() {
        let recorded = report
            .pull_bundle
            .as_ref()
            .map(|b| b.pull_bundle_sha256.clone());
        if pull_bundle.map(sha256_hex) != recorded {
            fail(
                &mut report,
                Stage::Package,
                None,
                "pull-bundle.tar.gz changed between generate and finalize".into(),
            );
        }
    }
    // The sandbox proves itself on every build: the Vector stage probes the
    // network before it runs anything, and any reachable target voids the
    // build, except the one reviewed exception (see `sandbox_egress_check`).
    // The check always records the open network; the report failure stays on
    // an earlier root cause if there was one (`fail` is first-wins, NAN-2969).
    let (sandbox, failure) = sandbox_egress_check(results.egress.as_deref(), sandbox_probe);
    if let Some(message) = failure {
        fail(&mut report, Stage::Sandbox, None, message);
    }
    report.checks.push(sandbox);
    if report.failure.is_none() && (results.skipped || results.validate.is_none()) {
        fail(
            &mut report,
            Stage::VectorValidate,
            None,
            "the Vector stage produced no result".into(),
        );
    }
    // NAN-2650: the runtime image must actually be Vector. `vector-check.sh`
    // records `vector --version` before anything else; an image without the
    // binary (staging once pinned the detection-jobs image) is refused here
    // with that reason instead of surfacing as an opaque validate exit code.
    if report.failure.is_none()
        && !results
            .version
            .as_deref()
            .is_some_and(|v| VECTOR_VERSION_RE.is_match(v))
    {
        let message = format!(
            "the runtime image {} has no `vector` binary (`vector --version` gave: {})",
            report.versions.runtime_image_digest,
            tail(results.version.as_deref().unwrap_or("<none>"))
        );
        fail(&mut report, Stage::Inputs, None, message);
    }

    // vector validate
    let mut validate = check("vector_validate", CheckStatus::Skipped, Vec::new());
    if let (None, Some(run)) = (&report.failure, &results.validate) {
        validate.duration_ms = Some(run.duration_ms);
        validate.exit_code = Some(run.exit_code);
        validate.output = Some(tail(&run.output));
        report.timings_ms.validate_ms = Some(run.duration_ms);
        if run.exit_code == 0 {
            validate.status = CheckStatus::Passed;
        } else {
            validate.status = CheckStatus::Failed;
            let (source, component) = attribute(&report, &run.output);
            fail_at(
                &mut report,
                Stage::VectorValidate,
                source,
                component,
                vector_error_excerpt(&run.output),
            );
        }
    }
    report.checks.push(validate);

    // vector test
    let mut test = check("vector_test", CheckStatus::Skipped, Vec::new());
    if let (None, Some(run)) = (&report.failure, &results.test) {
        test.duration_ms = Some(run.duration_ms);
        test.exit_code = Some(run.exit_code);
        test.output = Some(tail(&run.output));
        report.timings_ms.test_ms = Some(run.duration_ms);
        let clean = ANSI_RE.replace_all(&run.output, "");
        let seen: Vec<(String, bool)> = TEST_LINE_RE
            .captures_iter(&clean)
            .map(|c| (c[1].to_string(), &c[2] == "passed"))
            .collect();
        test.tests = seen
            .iter()
            .map(|(name, ok)| VectorTestCase {
                name: name.clone(),
                status: if *ok {
                    CheckStatus::Passed
                } else {
                    CheckStatus::Failed
                },
            })
            .collect();
        // Every tenant case must have run and passed.
        let mut missing_case = None;
        for source in report.sources.iter().filter(|s| s.changed && !s.components.is_empty()) {
            for index in 0..source.samples {
                let name = vector_tests::case_name(&source.slug, index);
                if !seen.iter().any(|(seen, ok)| *seen == name && *ok) {
                    missing_case.get_or_insert((source.slug.clone(), name));
                }
            }
        }
        if run.exit_code != 0 || missing_case.is_some() {
            test.status = CheckStatus::Failed;
            let source = missing_case.as_ref().map(|(slug, _)| slug.clone());
            let message = match &missing_case {
                Some((_, name)) => {
                    format!(
                        "{name} did not pass:\n{}",
                        vector_error_excerpt(&run.output)
                    )
                }
                None => vector_error_excerpt(&run.output),
            };
            fail(&mut report, Stage::VectorTest, source, message);
        } else {
            test.status = CheckStatus::Passed;
        }
    } else if report.failure.is_none() {
        fail(
            &mut report,
            Stage::VectorTest,
            None,
            "the Vector stage produced no test result".into(),
        );
    }
    report.checks.push(test);

    // NAN-3369: the pull bundle loads in the same Vector, in its own layout.
    // The check exists only for builds that carry a pull bundle, so every
    // other report (and its canonical digest) is unchanged.
    if report.pull_bundle.is_some() {
        let mut pull_check = check("vector_validate_pull", CheckStatus::Skipped, Vec::new());
        match (&report.failure, &results.pull_validate) {
            (None, Some(run)) => {
                pull_check.duration_ms = Some(run.duration_ms);
                pull_check.exit_code = Some(run.exit_code);
                pull_check.output = Some(tail(&run.output));
                if run.exit_code == 0 {
                    pull_check.status = CheckStatus::Passed;
                } else {
                    pull_check.status = CheckStatus::Failed;
                    let (source, component) = attribute(&report, &run.output);
                    fail_at(
                        &mut report,
                        Stage::VectorValidate,
                        source,
                        component,
                        format!("pull bundle: {}", vector_error_excerpt(&run.output)),
                    );
                }
            }
            (None, None) => fail(
                &mut report,
                Stage::VectorValidate,
                None,
                "the Vector stage produced no pull bundle validate result".into(),
            ),
            _ => {}
        }
        report.checks.push(pull_check);
    }

    if report.failure.is_some() {
        report.verdict = Verdict::Failed;
        // No artifact for a failed build: nothing unvalidated can be signed.
        report.bundle = None;
        report.pull_bundle = None;
    } else {
        report.verdict = Verdict::Passed;
    }
    report
}

// ---------------------------------------------------------------------------
// Canonical report digest
// ---------------------------------------------------------------------------

/// Domain tag of the canonical report digest (bump with any change to what
/// [`canonical_report_sha256`] covers).
pub const REPORT_DIGEST_DOMAIN: &str = "nano.parser_bundle_build.report_digest.v1";

/// Deterministic JSON: object keys sorted bytewise at every level, no
/// whitespace, serde_json's string/number encoding. Independent of whether
/// serde_json's `preserve_order` is enabled anywhere in the build graph.
fn write_canonical_json(value: &serde_json::Value, out: &mut String) {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).expect("a string serializes"));
                out.push(':');
                write_canonical_json(&map[key], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical_json(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&serde_json::to_string(other).expect("a scalar serializes")),
    }
}

fn canonical_sha256(value: &serde_json::Value) -> String {
    let mut text = String::with_capacity(4096);
    text.push_str(REPORT_DIGEST_DOMAIN);
    text.push('\n');
    write_canonical_json(value, &mut text);
    sha256_hex(text.as_bytes())
}

/// The build request's identity across rebuilds: `build.json` as parsed
/// (defaults made explicit), canonical, WITHOUT `build_id`.
fn build_request_sha256(request: &BuildRequest) -> String {
    let mut value = serde_json::to_value(request).expect("the build request serializes");
    if let Some(map) = value.as_object_mut() {
        map.remove("build_id");
    }
    canonical_sha256(&value)
}

/// The canonical `report_sha256`: sha256 over
/// `"nano.parser_bundle_build.report_digest.v1\n" + canonical JSON` of the
/// report with these removed:
///
/// * `build_id` (a fresh id per Job) and `report_sha256` (itself);
/// * `inputs.build_sha256` (raw `build.json` bytes, which carry `build_id`;
///   `inputs.build_request_sha256` covers the request instead);
/// * `timings_ms`, and `checks[].duration_ms`;
/// * `checks[].output` (the bounded tail of Vector's free-form diagnostics,
///   which may carry log timestamps; `status`, `exit_code`, `tests` and
///   `findings` stay).
///
/// Everything that decides WHAT was validated and HOW it came out stays in:
/// verdict, failure, input digests, versions, bundle facts, sources, checks,
/// merge. Two builds of identical inputs therefore carry the same digest, so
/// a rebuild after the Job's TTL, or a revert that rebuilds the same content,
/// reproduces the `composition.validation_report_sha256` 9001660 recorded.
pub fn canonical_report_sha256(report: &BuildReport) -> String {
    let mut value = serde_json::to_value(report).expect("the report serializes");
    if let Some(map) = value.as_object_mut() {
        map.remove("build_id");
        map.remove("report_sha256");
        map.remove("timings_ms");
        if let Some(inputs) = map.get_mut("inputs").and_then(|v| v.as_object_mut()) {
            inputs.remove("build_sha256");
        }
        if let Some(checks) = map.get_mut("checks").and_then(|v| v.as_array_mut()) {
            for check in checks.iter_mut().filter_map(|c| c.as_object_mut()) {
                check.remove("duration_ms");
                check.remove("output");
            }
        }
    }
    canonical_sha256(&value)
}

fn frame(out: &mut impl std::io::Write, path: &str, data: &[u8]) -> std::io::Result<()> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(data);
    let chunks: Vec<&str> = if encoded.is_empty() {
        vec![""]
    } else {
        encoded
            .as_bytes()
            .chunks(LOG_CHUNK_CHARS)
            .map(|c| std::str::from_utf8(c).expect("base64 is ASCII"))
            .collect()
    };
    let sha = sha256_hex(data);
    for (part, chunk) in chunks.iter().enumerate() {
        let line = serde_json::json!({
            "path": path, "sha256": sha, "bytes": data.len(),
            "part": part, "parts": chunks.len(), "data": chunk,
        });
        writeln!(out, "{LOG_FILE_PREFIX}{line}")?;
    }
    Ok(())
}

/// Anonymous `GET <url>` against the in-cluster API: the HTTP status, or the
/// error. No credentials, no proxy, no redirects. The pod has no cluster CA
/// (no token mount), so the certificate is not verified: this request only
/// has to show that an unauthenticated caller is refused, and it sends
/// nothing worth intercepting.
pub fn anonymous_api_status(url: &str) -> Result<u16, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    runtime.block_on(async {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| format!("client: {e}"))?;
        let response = client.get(url).send().await.map_err(|e| e.to_string())?;
        Ok(response.status().as_u16())
    })
}

/// The `finalize` stage: read `/work` + `/results`, write `/out`, frame the
/// outputs on stdout, and write the termination message. Tolerates no sandbox
/// egress; the Job entrypoint uses [`run_finalize_with_sandbox`].
pub fn run_finalize(
    work: &Path,
    results_dir: &Path,
    out: &Path,
    termination_log: Option<&Path>,
    runtime_image_digest: Option<&str>,
    stdout: &mut impl std::io::Write,
) -> Result<BuildSummary, TenantBundleError> {
    run_finalize_with_sandbox(
        work,
        results_dir,
        out,
        termination_log,
        runtime_image_digest,
        &|_, _| SandboxProbe::default(),
        stdout,
    )
}

/// [`run_finalize`] with a sandbox probe built from the Vector results
/// (`probe(results_dir, egress)`), e.g. [`SandboxProbe::gather`].
pub fn run_finalize_with_sandbox(
    work: &Path,
    results_dir: &Path,
    out: &Path,
    termination_log: Option<&Path>,
    runtime_image_digest: Option<&str>,
    probe: &dyn Fn(&Path, Option<&str>) -> SandboxProbe,
    stdout: &mut impl std::io::Write,
) -> Result<BuildSummary, TenantBundleError> {
    let report: BuildReport = serde_json::from_slice(&read(&work.join(GENERATE_REPORT_FILE))?)
        .map_err(|e| TenantBundleError::Io(format!("generate report: {e}")))?;
    let bundle_path = work.join(BUNDLE_FILE);
    let bundle = bundle_path
        .exists()
        .then(|| read(&bundle_path))
        .transpose()?;
    let pull_path = work.join(PULL_BUNDLE_FILE);
    let pull_bundle = pull_path.exists().then(|| read(&pull_path)).transpose()?;
    let results = VectorResults::read(results_dir);
    let sandbox = probe(results_dir, results.egress.as_deref());
    let mut report = finalize_report_with_pull(
        report,
        &results,
        &sandbox,
        bundle.as_deref(),
        pull_bundle.as_deref(),
        runtime_image_digest,
    );
    let report_sha256 = canonical_report_sha256(&report);
    report.report_sha256 = Some(report_sha256.clone());

    let report_bytes =
        serde_json::to_vec_pretty(&report).map_err(|e| TenantBundleError::Io(e.to_string()))?;
    write(&out.join(REPORT_FILE), &report_bytes)?;
    let io = |e: std::io::Error| TenantBundleError::Io(format!("stdout: {e}"));
    frame(stdout, REPORT_FILE, &report_bytes).map_err(io)?;
    if report.verdict == Verdict::Passed {
        if let Some(bundle) = &bundle {
            write(&out.join(BUNDLE_FILE), bundle)?;
            frame(stdout, BUNDLE_FILE, bundle).map_err(io)?;
        }
        if let (Some(pull), Some(_)) = (&pull_bundle, &report.pull_bundle) {
            write(&out.join(PULL_BUNDLE_FILE), pull)?;
            frame(stdout, PULL_BUNDLE_FILE, pull).map_err(io)?;
        }
    }
    if report.merge.is_some() {
        let diff = read(&work.join(MERGE_DIFF_FILE))?;
        write(&out.join(MERGE_DIFF_FILE), &diff)?;
        frame(stdout, MERGE_DIFF_FILE, &diff).map_err(io)?;
    }
    let summary = BuildSummary {
        schema_version: BUILD_SCHEMA_VERSION,
        build_id: report.build_id.clone(),
        tenant_id: report.tenant_id.clone(),
        purpose: report.purpose,
        verdict: report.verdict,
        failure_stage: report.failure.as_ref().map(|f| f.stage),
        content_sha256: report.bundle.as_ref().map(|b| b.content_sha256.clone()),
        report_sha256,
        report_file_sha256: sha256_hex(&report_bytes),
    };
    let summary_bytes =
        serde_json::to_vec(&summary).map_err(|e| TenantBundleError::Io(e.to_string()))?;
    write(&out.join(SUMMARY_FILE), &summary_bytes)?;
    writeln!(
        stdout,
        "{LOG_RESULT_PREFIX}{}",
        String::from_utf8_lossy(&summary_bytes)
    )
    .map_err(io)?;
    if let Some(path) = termination_log {
        // Best effort: outside Kubernetes the path may not exist.
        let _ = std::fs::write(path, &summary_bytes);
    }
    Ok(summary)
}

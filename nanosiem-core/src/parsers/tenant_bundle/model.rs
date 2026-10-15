// SPDX-License-Identifier: AGPL-3.0-or-later

//! Build inputs (`build.json`, `tenant-sources.json`) and the build report.
//!
//! These shapes are the contract with the rollout orchestrator (NAN-2606):
//! it writes the inputs into the build Job's immutable request ConfigMap and
//! reads the report back from the Job. Unknown fields are refused so a
//! mis-spelled knob fails loudly instead of being ignored.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use uuid::Uuid;

use super::TenantBundleError;

pub const BUILD_SCHEMA_VERSION: u32 = 1;
pub const REPORT_KIND: &str = "nano.parser_bundle_build.v1";

/// Per-tenant bounds. Generous for real tenants, small enough that one build
/// request always fits one ConfigMap and one bundle stays under the renderer's
/// 4 MiB packed bound.
pub const MAX_SOURCES: usize = 256;
pub const MAX_VRL_BYTES: usize = 256 * 1024;
pub const MAX_SAMPLES_PER_SOURCE: usize = 32;
pub const MAX_SAMPLE_BYTES: usize = 64 * 1024;
pub const MAX_TEXT_FIELD: usize = 255;
/// NAN-3369: at most this many pull sources per tenant pull bundle.
pub const MAX_PULL_SOURCES: usize = 64;
/// NAN-3712: at most this many lanes in a runtime-config pull bundle (the
/// pull runtime runs at most 32 sources, `PULL_SOURCE_CAP`).
pub const MAX_PULL_LANES: usize = 32;
/// NAN-3371 (P0-2): bounds of the rendered `aws_s3` SQS tuning.
pub const MAX_SQS_CLIENT_CONCURRENCY: u8 = 8;
pub const MAX_SQS_MESSAGES_PER_RECEIVE: u8 = 2;
/// NAN-3604: bounds of a pull source's `backlog_cutoff_unix_ms`
/// (2020-01-01T00:00:00Z ..= 2100-01-01T00:00:00Z), so a seconds value or a
/// garbage number is refused instead of skipping everything or nothing.
pub const MIN_BACKLOG_CUTOFF_UNIX_MS: u64 = 1_577_836_800_000;
pub const MAX_BACKLOG_CUTOFF_UNIX_MS: u64 = 4_102_444_800_000;

pub(crate) static TENANT_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9](?:[a-z0-9-]{0,62})$").expect("static regex"));
/// The renderer's `HEC_SOURCE_RE`: the slug grammar every route, credential
/// and delivery token uses.
pub(crate) static SOURCE_SLUG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9_-]{0,99}$").expect("static regex"));
static HEX_64_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-f0-9]{64}$").expect("static regex"));
static BUILD_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$").expect("static regex"));
static IMAGE_DIGEST_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^sha256:[a-f0-9]{64}$").expect("static regex"));

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildPurpose {
    /// Build the bundle a rollout will sign and activate.
    Rollout,
    /// Decision (a): rebuild the tenant's overlay on a newer platform base and
    /// report a diff and a verdict. The tenant's current bundle is untouched;
    /// only an explicit tenant action may roll the candidate.
    MergeCandidate,
}

/// `build.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildRequest {
    pub schema_version: u32,
    /// Orchestrator request id; echoed into the report.
    pub build_id: String,
    pub tenant_id: String,
    pub tenant_uuid: Uuid,
    pub purpose: BuildPurpose,
    /// The cell's pinned `runtimeImageDigest`. The Job runs the Vector checks
    /// in exactly this image; the report echoes it.
    pub runtime_image_digest: String,
    /// sha256 of `base.tar.gz`, the release-pinned platform base.
    pub base_sha256: String,
    /// sha256 of `current.tar.gz`, the tenant's live bundle. Required for
    /// `merge_candidate`, refused otherwise.
    #[serde(default)]
    pub current_sha256: Option<String>,
    /// Slugs whose samples `vector test` runs. `None` = every tenant source.
    #[serde(default)]
    pub changed_sources: Option<Vec<String>>,
    /// Fail a changed source that has no saved samples.
    #[serde(default)]
    pub require_samples: bool,
    /// NAN-3369: the tenant's enabled pull sources, from the server's
    /// pull-source rows. When present, the build also emits the lanes-subset
    /// pull bundle (`pull-bundle.tar.gz`) for the tenant's pull container.
    /// Absent (the default) = no pull bundle, and the request serializes
    /// exactly as before, so `build_request_sha256` / `report_sha256` of every
    /// existing request are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_sources: Option<Vec<PullSource>>,
    /// NAN-3712: build the runtime-config pull bundle
    /// ([`super::pull::PULL_RUNTIME_CONTRACT`]) for these lanes instead of
    /// rendering pull sources: the pull runtime renders its sources from the
    /// live rows and reloads Vector in place, so a source change needs no
    /// build. Sorted, unique source slugs (1..=[`MAX_PULL_LANES`]); exclusive
    /// with `pull_sources`. Absent (the default) serializes exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_lanes: Option<Vec<String>>,
    /// NAN-3623: the tenant's Worker renders `worker.pipe_capture`, so its
    /// pull bundle carries the Nano Pipe capture tap
    /// ([`super::pull::render_pull_sources`]). Requires `pull_sources` or
    /// `pull_lanes`.
    /// Absent/false (the default) serializes exactly as before, so every
    /// existing request keeps its `build_request_sha256` and every tenant
    /// without capture keeps its pull bundle bytes.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pull_capture: bool,
}

/// NAN-3369: the Vector source a pull source renders (Revision 2, §R1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PullSourceKind {
    /// S3 objects announced on an SQS queue (CloudTrail, ALB, VPC flow, ...).
    AwsS3,
    /// SQS message bodies.
    AwsSqs,
    /// A Pub/Sub subscription (GCP log sinks).
    GcpPubsub,
    /// NAN-3604: an Azure Event Hub over AMQP (the nano-rs/vector fork's
    /// `azure_event_hubs` source) with a customer blob checkpoint store.
    AzureEventHubs,
}

impl PullSourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AwsS3 => "aws_s3",
            Self::AwsSqs => "aws_sqs",
            Self::GcpPubsub => "gcp_pubsub",
            Self::AzureEventHubs => "azure_event_hubs",
        }
    }
}

/// One enabled pull source, exactly the server row's identity: the id the
/// platform stamps as `%nano_credential_id = "pull:<source_id>"`, the lane
/// slug it feeds, and the source kind. Queue/bucket/subscription coordinates
/// are NOT here: the Worker passes them as container env at start, so editing
/// a queue never rebuilds the bundle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullSource {
    pub source_id: Uuid,
    pub slug: String,
    pub kind: PullSourceKind,
    /// NAN-3371 (P0-2): `aws_s3` only. Vector's `aws_s3` source handles the
    /// messages of one receive serially and waits for each object's
    /// end-to-end ack (~1.9 s per object, ~30 objects/min per poller), and
    /// `client_concurrency` defaults to the CPU count (1 on a `basic`
    /// container). Rendered as `sqs.client_concurrency`; absent = 4
    /// ([`super::pull::DEFAULT_SQS_CLIENT_CONCURRENCY`]), range 1-8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sqs_client_concurrency: Option<u8>,
    /// NAN-3371 (P0-2): `aws_s3` only. Messages per receive, kept small so a
    /// stuck object holds few others behind it. Rendered as
    /// `sqs.max_number_of_messages`; absent = 1, range 1-2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sqs_max_number_of_messages: Option<u8>,
    /// NAN-3604: `aws_s3` / `aws_sqs` / `gcp_pubsub` only. Every pull source
    /// starts point-forward: a message the queue or subscription already held
    /// when the source was
    /// created is pre-existing backlog, so it is acked/deleted WITHOUT being
    /// ingested and counted as `component_discarded_events_total
    /// {component_id="nano_pull_<id>_skipped_backlog", intentional="true"}`.
    /// The cutoff is the source row's `created_at` (unix milliseconds); the
    /// render skips only events older than it by more than
    /// [`super::pull::BACKLOG_CUTOFF_GRACE_MS`] (clock skew). The event time is
    /// `aws_sqs`: the SQS `SentTimestamp`; `gcp_pubsub`: `publish_time`;
    /// `aws_s3`: the S3 notification's `eventTime`
    /// ([`super::pull::S3_EVENT_TIME_FIELD`]), else the object's
    /// `LastModified` on a Vector without it. Event Hubs
    /// needs none (`start_position = "latest"`). Absent = no skip filter, and the request and
    /// the render are byte-identical to before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backlog_cutoff_unix_ms: Option<u64>,
}

impl BuildRequest {
    pub fn validate(&self) -> Result<(), TenantBundleError> {
        let bad = |why: &str| Err(TenantBundleError::Input(why.to_string()));
        if self.schema_version != BUILD_SCHEMA_VERSION {
            return bad("build.json schema_version must be 1");
        }
        if !BUILD_ID_RE.is_match(&self.build_id) {
            return bad("build_id is malformed");
        }
        if !TENANT_ID_RE.is_match(&self.tenant_id) {
            return bad("tenant_id is malformed");
        }
        if !IMAGE_DIGEST_RE.is_match(&self.runtime_image_digest) {
            return bad("runtime_image_digest must be sha256:<64 hex>");
        }
        if !HEX_64_RE.is_match(&self.base_sha256) {
            return bad("base_sha256 must be 64 lowercase hex digits");
        }
        match (self.purpose, &self.current_sha256) {
            (BuildPurpose::MergeCandidate, Some(sha)) if HEX_64_RE.is_match(sha) => {}
            (BuildPurpose::MergeCandidate, _) => {
                return bad("merge_candidate requires current_sha256 (64 lowercase hex)");
            }
            (BuildPurpose::Rollout, Some(_)) => {
                return bad("current_sha256 is only meaningful for merge_candidate");
            }
            (BuildPurpose::Rollout, None) => {}
        }
        if let Some(changed) = &self.changed_sources {
            if changed.len() > MAX_SOURCES || changed.iter().any(|s| !SOURCE_SLUG_RE.is_match(s)) {
                return bad("changed_sources must be source slugs");
            }
        }
        if self.pull_capture && self.pull_sources.is_none() && self.pull_lanes.is_none() {
            return bad("pull_capture requires pull_sources or pull_lanes");
        }
        if let Some(lanes) = &self.pull_lanes {
            if self.pull_sources.is_some() {
                return bad("pull_lanes and pull_sources are exclusive");
            }
            if lanes.is_empty()
                || lanes.len() > MAX_PULL_LANES
                || lanes.iter().any(|s| !SOURCE_SLUG_RE.is_match(s))
                || lanes.windows(2).any(|w| w[0] >= w[1])
            {
                return bad("pull_lanes must be 1-32 sorted, unique source slugs");
            }
        }
        if let Some(pull) = &self.pull_sources {
            if pull.len() > MAX_PULL_SOURCES {
                return bad("too many pull_sources");
            }
            if pull.iter().any(|s| !SOURCE_SLUG_RE.is_match(&s.slug)) {
                return bad("pull_sources slugs must be source slugs");
            }
            let ids: std::collections::BTreeSet<Uuid> = pull.iter().map(|s| s.source_id).collect();
            if ids.len() != pull.len() || ids.contains(&Uuid::nil()) {
                return bad("pull_sources source_id must be unique and non-nil");
            }
            if pull.iter().any(|s| !super::pull::sqs_tuning_is_valid(s)) {
                return bad(
                    "pull_sources SQS tuning is aws_s3-only: sqs_client_concurrency 1-8, \
                     sqs_max_number_of_messages 1-2",
                );
            }
            if pull
                .iter()
                .any(|s| !super::pull::backlog_cutoff_is_valid(s))
            {
                return bad(super::pull::BACKLOG_CUTOFF_MESSAGE);
            }
        }
        Ok(())
    }
}

/// `tenant-sources.json`: the tenant's published parser versions, as the
/// orchestrator read them through the signed tenant read. Only this tenant's
/// rows; the build refuses a document naming another tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantSources {
    pub schema_version: u32,
    pub tenant_id: String,
    pub sources: Vec<TenantSource>,
}

/// One published tenant log source (its active `log_source_versions` row
/// joined with the `log_sources` metadata the generator needs).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantSource {
    /// Routing slug: the credential route, the HEC delivery token suffix and
    /// the stored `metadata.log_source`.
    pub slug: String,
    pub log_source_id: Uuid,
    /// `log_source_versions.id` / `.version_number` of the published version.
    pub version_id: i64,
    pub version_number: i32,
    pub name: String,
    #[serde(default)]
    pub parser_vrl: String,
    #[serde(default)]
    pub extension_vrl: Option<String>,
    #[serde(default)]
    pub extension_enabled: bool,
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default = "default_namespace")]
    pub namespace: String,
    #[serde(default = "default_timezone")]
    pub timezone: String,
    #[serde(default)]
    pub sampling_ratio: Option<f64>,
    #[serde(default)]
    pub sampling_exclude_condition: Option<String>,
    /// Set when this source is the tenant's fork of a platform parser (the
    /// platform slug it was forked from). Upstream changes to that platform
    /// parser are reported for merge; they are never applied over the fork.
    #[serde(default)]
    pub forked_from: Option<String>,
    /// Saved raw samples (AddFeed step 2), run through `vector test`.
    #[serde(default)]
    pub samples: Vec<String>,
}

fn default_namespace() -> String {
    "default".into()
}
fn default_timezone() -> String {
    "UTC".into()
}

impl TenantSources {
    pub fn validate(&self, tenant_id: &str) -> Result<(), TenantBundleError> {
        let bad = |why: String| Err(TenantBundleError::Input(why));
        if self.schema_version != BUILD_SCHEMA_VERSION {
            return bad("tenant-sources.json schema_version must be 1".into());
        }
        if self.tenant_id != tenant_id {
            return bad("tenant-sources.json names a different tenant than build.json".into());
        }
        if self.sources.len() > MAX_SOURCES {
            return bad(format!("at most {MAX_SOURCES} tenant sources per bundle"));
        }
        for source in &self.sources {
            let slug = &source.slug;
            if !SOURCE_SLUG_RE.is_match(slug) {
                return bad(format!("source slug {slug:?} is malformed"));
            }
            if source.name.trim().is_empty() || source.name.len() > MAX_TEXT_FIELD {
                return bad(format!("{slug}: name must be 1-{MAX_TEXT_FIELD} bytes"));
            }
            for (field, value) in [
                ("vendor", source.vendor.as_deref()),
                ("product", source.product.as_deref()),
                ("category", source.category.as_deref()),
                ("namespace", Some(source.namespace.as_str())),
                ("timezone", Some(source.timezone.as_str())),
                ("forked_from", source.forked_from.as_deref()),
            ] {
                if value.is_some_and(|v| v.len() > MAX_TEXT_FIELD) {
                    return bad(format!("{slug}: {field} exceeds {MAX_TEXT_FIELD} bytes"));
                }
            }
            if source
                .forked_from
                .as_deref()
                .is_some_and(|f| !SOURCE_SLUG_RE.is_match(f))
            {
                return bad(format!("{slug}: forked_from is not a source slug"));
            }
            let extension = source.extension_vrl.as_deref().unwrap_or("");
            crate::parsers::pipe::stored_plan(&source.parser_vrl)
                .map_err(|message| TenantBundleError::Input(format!("{slug}: {message}")))?;
            // Extensions remain separate remaps. Reject a native graph here,
            // rather than rendering an aborting remap from a valid-looking plan.
            crate::parsers::pipe::runtime_program(extension)
                .map_err(|message| TenantBundleError::Input(format!("{slug}: source extension: {message}; move native steps into the processing plan")))?;
            if source.parser_vrl.len() > MAX_VRL_BYTES || extension.len() > MAX_VRL_BYTES {
                return bad(format!("{slug}: VRL exceeds {MAX_VRL_BYTES} bytes"));
            }
            let has_extension = source.extension_enabled && !extension.trim().is_empty();
            if source.parser_vrl.trim().is_empty() && !has_extension {
                return bad(format!("{slug}: no parser VRL and no enabled extension"));
            }
            if let Some(ratio) = source.sampling_ratio {
                if !(ratio.is_finite() && ratio > 0.0 && ratio <= 1.0) {
                    return bad(format!("{slug}: sampling_ratio must be in (0, 1]"));
                }
            }
            if source
                .sampling_exclude_condition
                .as_deref()
                .is_some_and(|c| c.len() > 4096 || c.contains(['\n', '\r']))
            {
                return bad(format!(
                    "{slug}: sampling_exclude_condition must be one line"
                ));
            }
            if source.samples.len() > MAX_SAMPLES_PER_SOURCE {
                return bad(format!("{slug}: at most {MAX_SAMPLES_PER_SOURCE} samples"));
            }
            if source.samples.iter().any(|s| s.len() > MAX_SAMPLE_BYTES) {
                return bad(format!("{slug}: a sample exceeds {MAX_SAMPLE_BYTES} bytes"));
            }
        }
        let mut slugs: Vec<&str> = self.sources.iter().map(|s| s.slug.as_str()).collect();
        slugs.sort_unstable();
        if slugs.windows(2).any(|pair| pair[0] == pair[1]) {
            return bad("a source slug is declared twice".into());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Passed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Inputs,
    /// The build pod could open a network connection: the sandbox is broken,
    /// so nothing it produced is trusted.
    Sandbox,
    Overlay,
    StructuralGuard,
    VectorValidate,
    VectorTest,
    Package,
}

/// Why a build failed: the stage, the component when one is known, and the
/// message the SIEM shows (for Vector stages, Vector's own error text).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    pub stage: Stage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardFinding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub rule: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorTestCase {
    pub name: String,
    pub status: CheckStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Check {
    pub name: String,
    pub status: CheckStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<GuardFinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tests: Vec<VectorTestCase>,
    /// Bounded tail of the tool's combined output (Vector's diagnostics).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// A named, reviewed exception a `passed` check carries (NAN-2987): today
    /// only `sandbox_egress` = [`SANDBOX_EXCEPTION_K8S_API_UNAUTHENTICATED`].
    /// Absent on every check that passed without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exception: Option<String>,
}

/// The one tolerated `sandbox_egress` exception (NAN-2987): the in-cluster
/// Kubernetes API is reachable, but the pod holds no token and anonymous
/// `GET /api` is refused. The platform's verifier accepts no other value.
pub const SANDBOX_EXCEPTION_K8S_API_UNAUTHENTICATED: &str = "k8s_api_unauthenticated";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceReport {
    pub slug: String,
    pub log_source_id: Uuid,
    pub version_id: i64,
    pub version_number: i32,
    pub file: String,
    pub components: Vec<String>,
    pub changed: bool,
    pub samples: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forked_from: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleOutput {
    /// sha256 of `bundle.tar.gz` — the manifest's `contentSha256`.
    pub content_sha256: String,
    pub gzip_bytes: u64,
    /// Where the orchestrator stores it:
    /// `tenants/<tenant_uuid>/parser-bundles/<sha>.tar.gz` - the UUID form the
    /// Worker renderer derives and 9001660 records, never the tenant slug.
    pub object_key: String,
    /// Sorted platform + tenant slugs: the source authority's `hec_sources`.
    pub hec_sources: Vec<String>,
    /// sha256 of `02-hec-source.toml`: the source authority's `hec_config_sha256`.
    pub hec_config_sha256: String,
    /// sha256 of `07-output-guards.toml` (unchanged from the base).
    pub output_guard_sha256: String,
    pub tenant_sources: Vec<String>,
}

/// NAN-3369: the lanes-subset pull bundle (`pull-bundle.tar.gz`), present
/// when the request named at least one pull source whose lane the tenant has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullBundleOutput {
    /// sha256 of `pull-bundle.tar.gz`: what the platform signs and the pull
    /// container's `runtimeEnvironmentSha256` carries.
    pub pull_bundle_sha256: String,
    pub gzip_bytes: u64,
    /// `tenants/<tenant_uuid>/pull-bundles/<sha>.tar.gz`.
    pub object_key: String,
    /// sha256 of the packed filtered base ([`super::pull::pull_base`]) the
    /// pull bundle was verified against: rederivable from the platform base
    /// and `pull_sources`, so any verifier can repeat the structural guard.
    pub base_sha256: String,
    /// The lane filter actually rendered (sorted, unique slugs).
    pub lane_sources: Vec<String>,
    /// The rendered pull sources, sorted by `source_id`.
    pub pull_sources: Vec<PullSource>,
    /// NAN-3653: the bundle carries the pull origin stamp
    /// ([`super::pull::PULL_ORIGIN_MARKER`]): every builder since NAN-3653
    /// stamps, and says so here. The verifier (the platform) rederives the
    /// filtered base with or without the stamp from this field, so it gates on
    /// what the pinned builder can do, never on a request field an older
    /// builder would refuse. Absent in reports of older builders.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pull_origin: bool,
    /// NAN-3712: set (to [`super::pull::PULL_RUNTIME_CONTRACT`]) for a
    /// runtime-config pull bundle, whose `pull_sources` is empty: its sources
    /// are rendered by the pull runtime from the live rows. Absent for a
    /// bundle with rendered sources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_runtime_contract: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputDigests {
    /// sha256 of the raw `build.json` bytes (carries `build_id`, so it
    /// differs per build; excluded from the canonical `report_sha256`).
    pub build_sha256: String,
    /// sha256 of `build.json` re-serialized canonically WITHOUT `build_id`:
    /// the build request's identity across rebuilds. In `report_sha256`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_request_sha256: Option<String>,
    pub tenant_sources_sha256: String,
    pub base_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Versions {
    pub builder: String,
    pub runtime_image_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vector: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkUpstream {
    pub slug: String,
    pub forked_from: String,
    /// The platform parser file backing `forked_from` in the new base.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_file: Option<String>,
    /// Did that platform parser change between the current and the new base?
    pub upstream_changed: bool,
}

/// Decision (a): what a merge candidate offers the tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeReport {
    /// Always false: a candidate never replaces the live bundle by itself.
    pub replaces_current: bool,
    pub current_sha256: String,
    /// Platform files that differ between the current bundle's base and the
    /// new base (the "platform update available" list).
    pub platform_files_changed: Vec<String>,
    /// Tenant overlay files that differ between current and candidate.
    pub overlay_files_changed: Vec<String>,
    pub fork_upstream: Vec<ForkUpstream>,
    /// `merge.diff` (unified, current → candidate) and its sha256.
    pub diff_path: String,
    pub diff_sha256: String,
    pub diff_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Timings {
    pub generate_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validate_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_ms: Option<u64>,
    pub package_ms: u64,
}

/// `report.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BuildReport {
    pub schema_version: u32,
    pub kind: String,
    pub build_id: String,
    pub tenant_id: String,
    pub tenant_uuid: Uuid,
    pub purpose: BuildPurpose,
    pub verdict: Verdict,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<Failure>,
    pub inputs: InputDigests,
    pub versions: Versions,
    /// Present only when the verdict is `passed`; a failed build emits no
    /// artifact, so nothing unvalidated can reach signing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<BundleOutput>,
    pub sources: Vec<SourceReport>,
    pub checks: Vec<Check>,
    pub timings_ms: Timings,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge: Option<MergeReport>,
    /// NAN-3369: the pull bundle (passed builds only, like `bundle`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_bundle: Option<PullBundleOutput>,
    /// NAN-3369: requested pull sources with no lane in this tenant's
    /// sources: not rendered, nothing is pulled. Never dropped silently: the
    /// the platform reconciler moves each to `failed` with
    /// "parser lane <slug> is not deployed" (NAN-3657), and the API refuses to
    /// create or re-verify one whose lane is not deployed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pull_pending: Vec<PullSource>,
    /// NAN-3712: requested runtime lanes (`pull_lanes`) the tenant has no
    /// source for: not in the runtime bundle, so the pull runtime cannot run a
    /// source of them until the lane is deployed. Never dropped silently.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pull_pending_lanes: Vec<String>,
    /// The canonical report digest ([`super::build::canonical_report_sha256`]),
    /// set by `finalize`. It excludes itself, `build_id`, the raw
    /// `inputs.build_sha256` and every timing / tool-output field, so two
    /// builds of identical inputs carry the same value. This is what the
    /// orchestrator records as `composition.validation_report_sha256`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_sha256: Option<String>,
}

/// The one-line summary written to the pod termination message
/// (`/dev/termination-log`, kept far under Kubernetes' 4096-byte cap).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildSummary {
    pub schema_version: u32,
    pub build_id: String,
    pub tenant_id: String,
    pub purpose: BuildPurpose,
    pub verdict: Verdict,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_stage: Option<Stage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_sha256: Option<String>,
    /// The canonical report digest (== `report.json`'s `report_sha256`):
    /// stable across rebuilds of identical inputs. Record THIS as
    /// `composition.validation_report_sha256`.
    pub report_sha256: String,
    /// sha256 of the exact `report.json` bytes (integrity of the file; it
    /// changes with every build because the file carries `build_id` and
    /// timings).
    #[serde(default)]
    pub report_file_sha256: String,
}

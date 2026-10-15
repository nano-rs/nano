// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3369: the lanes-subset **pull bundle** for a tenant's pull container
//! (NAN-3288 Revision 2, §R1/R2).
//!
//! A pull container pulls from the tenant's cloud (SQS/S3, SQS, Pub/Sub,
//! Event Hubs), parses with the tenant's lanes and writes Bronze itself. It must
//! never run the full tenant bundle: only the lanes of its pull sources, so the
//! VRL surface inside the internet-enabled container is exactly those lanes.
//!
//! ```text
//! platform base ──pull_base(pull sources)──▶ filtered base
//!   - every push source (HEC, OTLP, http, Vector native, Cloudflare direct,
//!     enrichment) and everything only they fed, transitively;
//!   - every platform lane (route) except `generic` (the audit plumbing lane,
//!     legacy platform parsers);
//!   + `05-pull-sources.toml`: one platform source + stamp remap per pull source
//! filtered base ──apply_overlay_with(lane_filter sources, Pull)──▶ pull bundle
//!   verified by verify_against_base_with(filtered base, pull bundle, Pull)
//! ```
//!
//! The lane filter is the set of pull-source slugs. The tenant lane for a slug
//! is the tenant's published source for it: on a zero base every catalog lane
//! is a tenant-installed source, and the tenant's override of it is simply its
//! published version, so "catalog lane + the tenant's overrides" is that one
//! generated `tenant__<slug>.toml` — byte-identical to the file in the full
//! bundle (checked by the build).
//!
//! Everything is line-level, like the overlay: platform bytes that survive
//! are untouched, so the filtered base is deterministic and its digest is
//! reproducible by any verifier from the platform base and the pull sources.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;
use uuid::Uuid;

use super::archive::BundleTree;
use super::model::{PullSource, PullSourceKind, TenantSource, SOURCE_SLUG_RE};
use super::overlay::{self, LAKE_SINK_FILE, ROUTER_FILE};
use super::TenantBundleError;

/// The platform file carrying the pull sources and their stamp remaps.
pub const PULL_SOURCES_FILE: &str = "05-pull-sources.toml";
/// Component prefix of everything [`render_pull_sources`] declares. A base
/// that already uses it is refused.
pub const PULL_COMPONENT_PREFIX: &str = "nano_pull_";
/// Source types the pull base keeps: the container's own telemetry (the
/// metrics exporter the Worker scrapes, the loss probe, collector errors).
/// Deliberately NOT `host_metrics` (NAN-3371, P0-4): its `process` collector
/// adds a series per short-lived thread (~300 KB per scrape and growing), and
/// every scrape reply is metered container egress. A base `host_metrics`
/// source is pruned like a push source, with everything only it fed.
pub const KEPT_SOURCE_TYPES: [&str; 2] = ["internal_metrics", "internal_logs"];
/// The Bronze sink: it must survive, with end-to-end acknowledgements on.
pub const BRONZE_SINK: &str = "ocsf_parquet_bronze";
pub const LAKE_PREPARE: &str = "ocsf_lake_storage_prepare";
const SOURCE_ROUTER: &str = "source_router";
const KEPT_DIRS: [&str; 2] = ["sources/parsers", "sources/configs"];
const GENERIC_ROUTE: &str = "generic";
/// AWS endpoint of the tenant-bound re-sign handler (design D-C): the
/// container never holds an AWS credential; the static keys are inert and
/// the Worker handler re-signs every request with broker-minted credentials.
pub const AWS_RESIGN_ENDPOINT: &str = "http://aws.internal";
pub const INERT_CREDENTIAL: &str = "nano-pull-inert";
/// NAN-3604: the Azure credential every `azure_event_hubs` source and its blob
/// checkpoint store use. `managed_identity` with a user-assigned client id
/// makes azure_identity call the App Service managed-identity endpoint the
/// container env names (`IDENTITY_ENDPOINT=http://entra.internal/msi/token`),
/// which the tenant-bound Worker handler answers with a broker-minted,
/// resource-scoped Entra access token. No assertion, secret or SAS is ever in
/// the container.
pub const AZURE_CREDENTIAL_KIND: &str = "managed_identity";
/// `user_assigned_managed_identity_id_type` (fork `UserAssignedManagedIdentityIdType`).
pub const AZURE_IDENTITY_ID_TYPE: &str = "client_id";
/// How often acknowledged positions are written to the checkpoint container.
pub const AZURE_CHECKPOINT_INTERVAL_SECS: u32 = 5;
/// NAN-3604: where a partition with no checkpoint starts. Every pull source
/// starts point-forward: `earliest` would ingest the hub's whole retention
/// (up to 7 days, 90 on premium) on the first start. There is deliberately no
/// per-source backfill option; one would be explicit, time-bounded and
/// rate-limited, and a separate decision.
pub const AZURE_START_POSITION: &str = "latest";
/// NAN-3604: suffix of the `aws_s3` / `aws_sqs` / `gcp_pubsub` backlog filter
/// (`nano_pull_<id>_skipped_backlog`), rendered when the row carries
/// `backlog_cutoff_unix_ms`. Its intentional discards are the source's
/// skipped-backlog count (never loss: `LOSS_FENCE_CONTRACT` item 1).
pub const SKIPPED_BACKLOG_SUFFIX: &str = "_skipped_backlog";
/// NAN-3604: an event is backlog only when it is older than the source's
/// creation by more than this, so clock skew between the control DB and the
/// cloud never skips a message sent just after the customer connected the
/// source.
pub const BACKLOG_CUTOFF_GRACE_MS: u64 = 300_000;
/// NAN-3604: the top-level field (legacy namespace) the nano Vector fork's
/// `aws_s3` source adds in SQS mode: the S3 event notification's `eventTime`,
/// i.e. when S3 accepted the object (Vector namespace: `%aws_s3.event_time`;
/// the pull bundle runs the legacy namespace). The `aws_s3` backlog filter
/// dates an event by it, NOT by `.timestamp` (the object's `LastModified`), so
/// a restored or copied object whose `LastModified` predates the source still
/// ingests. A Vector without the field falls back to `.timestamp`. The stamp
/// deletes it, so the lane's parsers see the same event as before.
pub const S3_EVENT_TIME_FIELD: &str = "s3_event_time";
/// `BuildRequest::validate`'s refusal for a bad `backlog_cutoff_unix_ms`.
pub const BACKLOG_CUTOFF_MESSAGE: &str =
    "pull_sources backlog_cutoff_unix_ms is aws_s3/aws_sqs/gcp_pubsub-only, unix milliseconds in 2020-2100";
/// Container-global env the Worker sets when a definition has an Azure source
/// (DESIGN §9; not secret).
pub const AZURE_IDENTITY_ENDPOINT: &str = "http://entra.internal/msi/token";
pub const AZURE_IDENTITY_HEADER: &str = INERT_CREDENTIAL;
/// SQS visibility for a pulled message: longer than any Bronze stall the
/// sink rides out (`retry_max_duration_secs = 300` plus batching).
pub const SQS_VISIBILITY_TIMEOUT_SECS: u32 = 900;
/// Pub/Sub ack deadline (the maximum).
pub const PUBSUB_ACK_DEADLINE_SECS: u32 = 600;
/// NAN-3371 (P0-2): `sqs.client_concurrency` when the source row names none.
/// `aws_s3` waits for each object's end-to-end ack before the next one of the
/// same receive, so one poller moves ~30 objects/min; the work is I/O-bound.
pub const DEFAULT_SQS_CLIENT_CONCURRENCY: u8 = 4;
/// NAN-3371 (P0-2): `sqs.max_number_of_messages` when the row names none: one
/// message per receive, so a stuck object holds no other message invisible.
pub const DEFAULT_SQS_MAX_NUMBER_OF_MESSAGES: u8 = 1;
/// NAN-3371 (P0-2): the lowest Bronze-sink retry backoff cap
/// (`request.retry_max_duration_secs`) a pull bundle accepts. Every retry of
/// a stalled batch is metered container egress, so a pull container must not
/// hammer a stalled edge log every few seconds; the platform base caps at
/// 300 s, which also stays under the SQS visibility above.
pub const MIN_BRONZE_RETRY_BACKOFF_CAP_SECS: i64 = 60;
/// NAN-3372 (P0-3, decision D-L): the GCP token contract of the pull class's
/// `metadata.google.internal` handler (the Worker-side token handler Vector's
/// GCP auth falls back to; it does not exist yet). It must mint Pub/Sub
/// access tokens at the 1 h maximum and report `expires_in` honestly: Vector
/// refreshes at `expires_in - 200 s` and every refresh restarts the
/// StreamingPull stream, dropping in-flight acks (0.7-4.6 % duplicates at a
/// 300 s TTL, ~0.03 % at 1 h). Revocation = the broker refuses to re-mint,
/// plus a container restart when it must be immediate.
pub const GCP_PUBSUB_TOKEN_LIFETIME_SECS: u32 = 3600;
/// NAN-3371: object keys under this path segment are CloudTrail digest files
/// (no `Records`), never events.
pub const CLOUDTRAIL_DIGEST_SEGMENT: &str = "CloudTrail-Digest/";
/// The lane slug whose `aws_s3` objects are CloudTrail log files.
pub const CLOUDTRAIL_SLUG: &str = "aws_cloudtrail";
/// NAN-3371 / NAN-3372: the pull loss-accounting exporter (see
/// [`LOSS_FENCE_CONTRACT`]). Small on purpose: every scrape reply is metered
/// container egress, so the pull Worker scrapes this, never the full
/// `prometheus_metrics` page on 9598.
pub const PULL_LOSS_EXPORTER_ADDRESS: &str = "0.0.0.0:9597";
pub const PULL_LOSS_SOURCE: &str = "nano_pull_loss_metrics";
pub const PULL_LOSS_SELECT: &str = "nano_pull_loss_select";
pub const PULL_LOSS_EXPORTER: &str = "nano_pull_loss_exporter";

/// NAN-3371 / NAN-3372: what the pull loss fence (the pull DO's scrape of
/// [`PULL_LOSS_EXPORTER_ADDRESS`]) must compute. A discard that the source
/// keeps for the customer's DLQ is NOT loss, so the fence never alarms on
/// `component_discarded_events_total > 0` alone:
///
/// 1. `component_discarded_events_total{intentional="true"}`: by design
///    (filter/sample/dedupe). Never an alarm. NAN-3604: on
///    `nano_pull_<id>_skipped_backlog` it is the source's skipped pre-existing
///    queue/subscription backlog (acked, never ingested): reported per
///    source, never loss.
///    (CloudTrail digest files are
///    not events at all: the stamp emits nothing for them and their message
///    is acked like a filtered event, with no discard counted.)
/// 2. Pull class `r2.internal` (D-K, `handlePullR2Put` in
///    `workers/hosted-ingest/src/r2-bridge.js`) answers 200 for a batch the
///    edge log refuses as non-retryable (400/412) after quarantining it under
///    `pull-dead-letter-v1/tenant_uuid=<uuid>/`, and answers the quarantine
///    with `x-nano-pull-quarantined`. Those batches are acknowledged, so the
///    customer's message is deleted/acked and nothing is discarded; the
///    dead-letter prefix is the receipt. Count them from the handler's log,
///    not from Vector.
/// 3. `component_discarded_events_total{component_id="ocsf_parquet_bronze",
///    intentional="false"}` therefore means the handler refused WITHOUT
///    quarantine (403 tenant/route mismatch, 413). For `aws_s3`/`aws_sqs`
///    sources the message is kept (`delete_failed_message = false`) and lands
///    in the customer's DLQ: HELD, not lost, visible as
///    `sqs_message_received_messages_total - sqs_message_delete_succeeded_total`
///    growing on the `nano_pull_<id>` source. For `gcp_pubsub` it is re-leased
///    on the next stream restart; for `azure_event_hubs` the
///    checkpoint advances past it (Rejected is not replayed: LOST). Alarm on it
///    (it is a misconfiguration either way), classifying held vs lost by the
///    bundle's source kinds.
/// 4. Any other `intentional="false"` discard (a transform or the lake
///    prepare) is loss: alarm.
/// 5. Progress: `component_received_events_total` on `nano_pull_<id>` vs
///    `component_sent_events_total` on `ocsf_parquet_bronze`, plus
///    `component_errors_total` on both, so a wedged source (no receives) or a
///    stuck sink (receives, no sends) is visible.
/// 6. Liveness: `component_sent_events_total` on [`PULL_LOSS_SOURCE`] (the
///    exporter's own `internal_metrics` source) advances every scrape interval
///    even with no traffic; the pull Worker's scrape marker is that counter, so
///    an idle tenant is not mistaken for a wedged Vector (NAN-3381).
pub const LOSS_FENCE_CONTRACT: &str = "nano-pull-loss-fence-v1";

/// NAN-3623 (Nano Pipe live capture of pull events): component prefix of the
/// opt-in capture tap ([`render_capture_tap`]). Deliberately NOT under
/// [`PULL_COMPONENT_PREFIX`], so the loss fence never counts the tap as a pull
/// component; a capture render also keeps its discards out of the exporter.
pub const CAPTURE_COMPONENT_PREFIX: &str = "nano_pipe_capture_";
/// The tenant-bound Worker handler the tap talks to (workers/hosted-ingest
/// `pull-capture.js`, installed only when the tenant Worker renders
/// `worker.pipe_capture`). The container holds no capture credential.
pub const PIPE_CAPTURE_HOST: &str = "capture.internal";
pub const CAPTURE_STATUS_URI: &str = "http://capture.internal/v1/status";
pub const CAPTURE_OBSERVE_URI: &str = "http://capture.internal/v1/observe";
/// How often the tap asks which pull lanes have a running capture session.
/// With no session this poll and one memory-table miss per event is ALL the
/// work the tap adds.
pub const CAPTURE_STATUS_INTERVAL_SECS: u32 = 2;
/// A lane stays "capturing" this long after the last status naming it.
pub const CAPTURE_SESSION_TTL_SECS: u32 = 6;
/// Sampling: at most this many events per second per lane reach the buffer
/// (a session keeps at most 1000 events / 64 KiB in any case).
pub const CAPTURE_EVENTS_PER_SEC_PER_LANE: u32 = 20;
/// A pulled event longer than this is not captured; it only marks the
/// session truncated (as a push prefix cut at 64 KiB does).
pub const CAPTURE_MAX_MESSAGE_BYTES: u32 = 32768;
/// The capture buffer's ceiling; inserts above it are dropped, never queued.
pub const CAPTURE_BUFFER_MAX_BYTES: u32 = 1_048_576;

/// NAN-3712: the runtime-config pull bundle. A runtime bundle is code only:
/// it carries no pull source. The pull runtime renders its sources from the
/// live rows (`nano_shared.resolve_pull_runtime_sources()`) with
/// [`runtime_template`] + [`substitute_runtime_template`], writes them to
/// [`PULL_RUNTIME_SOURCES_FILE`] under [`PULL_RUNTIME_CONFIG_DIR`] and reloads
/// Vector in place (SIGHUP), so a source add, edit or pause needs no build, no
/// Worker render and no container restart. The router and the capture tap
/// take every stamp through [`PULL_STAMP_GLOB`]; the origin stamp reads the
/// provider the source stamp sets (`%nano_pull_provider`). The bundle's
/// `05-pull-sources.toml` starts with [`PULL_RUNTIME_MARKER`]: the Worker
/// renderer refuses a runtime intent whose bundle does not carry the contract
/// it renders templates for, so templates and bundle never skew.
pub const PULL_RUNTIME_CONTRACT: &str = "nano-pull-runtime-v1";
/// First line of a runtime bundle's `05-pull-sources.toml`
/// (`# <PULL_RUNTIME_CONTRACT>: ...`).
pub const PULL_RUNTIME_MARKER: &str =
    "# nano-pull-runtime-v1: pull sources are runtime config (NAN-3712), not bundle bytes.";
/// The router's and the capture tap's inputs in a runtime bundle: every
/// source stamp, whatever sources the runtime config declares. Nothing else
/// the bundle declares ends in `_stamp` under [`PULL_COMPONENT_PREFIX`].
pub const PULL_STAMP_GLOB: &str = "nano_pull_*_stamp";
/// Where the pull runtime writes [`PULL_RUNTIME_SOURCES_FILE`], relative to the
/// cell root (an extra `--config-dir`; the build's Vector stage loads its
/// sample there too).
pub const PULL_RUNTIME_CONFIG_DIR: &str = "dynamic/pull";
pub const PULL_RUNTIME_SOURCES_FILE: &str = "pull-runtime-sources.toml";

static INTERPOLATION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{[^}]*\}").expect("static regex"));
static BARE_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]+$").expect("static regex"));

fn base_err(message: impl Into<String>) -> TenantBundleError {
    TenantBundleError::Base(format!("pull bundle: {}", message.into()))
}

// ---------------------------------------------------------------------------
// Pull source naming and rendering
// ---------------------------------------------------------------------------

/// `nano_pull_<source_id simple hex>`: the Vector source id.
pub fn source_component(source: &PullSource) -> String {
    format!("{PULL_COMPONENT_PREFIX}{}", source.source_id.simple())
}

/// The platform stamp remap right after the source.
pub fn stamp_component(source: &PullSource) -> String {
    format!("{}_stamp", source_component(source))
}

/// Prefix of the container env the Worker sets for this source's coordinates
/// (`NANO_PULL_<HEX>_QUEUE_URL`, ...). Coordinates are env, not bundle bytes,
/// so a queue edit restarts the container without a rebuild.
pub fn env_prefix(source: &PullSource) -> String {
    format!(
        "NANO_PULL_{}_",
        source.source_id.simple().to_string().to_ascii_uppercase()
    )
}

/// `%nano_credential_id` of every event this source emits.
pub fn credential_id(source: &PullSource) -> String {
    format!("pull:{}", source.source_id.hyphenated())
}

/// NAN-3371: the `aws_s3` SQS tuning is in range and only on `aws_s3`.
pub fn sqs_tuning_is_valid(source: &PullSource) -> bool {
    use super::model::{MAX_SQS_CLIENT_CONCURRENCY, MAX_SQS_MESSAGES_PER_RECEIVE};
    let tuned =
        source.sqs_client_concurrency.is_some() || source.sqs_max_number_of_messages.is_some();
    (!tuned || source.kind == PullSourceKind::AwsS3)
        && source
            .sqs_client_concurrency
            .is_none_or(|n| (1..=MAX_SQS_CLIENT_CONCURRENCY).contains(&n))
        && source
            .sqs_max_number_of_messages
            .is_none_or(|n| (1..=MAX_SQS_MESSAGES_PER_RECEIVE).contains(&n))
}

/// NAN-3604: the backlog cutoff is in range and only on a queue/subscription
/// kind (Event Hubs starts point-forward through `start_position`).
pub fn backlog_cutoff_is_valid(source: &PullSource) -> bool {
    use super::model::{MAX_BACKLOG_CUTOFF_UNIX_MS, MIN_BACKLOG_CUTOFF_UNIX_MS};
    match source.backlog_cutoff_unix_ms {
        None => true,
        Some(ms) => {
            matches!(
                source.kind,
                PullSourceKind::AwsS3 | PullSourceKind::AwsSqs | PullSourceKind::GcpPubsub
            ) && (MIN_BACKLOG_CUTOFF_UNIX_MS..=MAX_BACKLOG_CUTOFF_UNIX_MS).contains(&ms)
        }
    }
}

/// `nano_pull_<id>_skipped_backlog`: the backlog filter between the source
/// and its stamp, when the source has a cutoff.
pub fn backlog_component(source: &PullSource) -> Option<String> {
    source
        .backlog_cutoff_unix_ms
        .map(|_| format!("{}{SKIPPED_BACKLOG_SUFFIX}", source_component(source)))
}

/// Split requested pull sources into those with a lane among the tenant's
/// sources (rendered, sorted by id) and those without (reported in
/// `pull_pending`; the reconciler fails them, NAN-3657).
pub fn plan(sources: &[TenantSource], pull: &[PullSource]) -> (Vec<PullSource>, Vec<PullSource>) {
    let lanes: BTreeSet<&str> = sources.iter().map(|s| s.slug.as_str()).collect();
    let mut sorted = pull.to_vec();
    sorted.sort();
    sorted
        .into_iter()
        .partition(|p| lanes.contains(p.slug.as_str()))
}

fn render_source(out: &mut String, source: &PullSource) {
    let id = source_component(source);
    let env = env_prefix(source);
    let header = |out: &mut String, sub: &str| {
        out.push_str(&format!("\n[sources.{id}{sub}]\n"));
    };
    out.push_str(&format!(
        "# Pull source {} ({}) -> lane {}.\n",
        source.source_id.hyphenated(),
        source.kind.as_str(),
        source.slug
    ));
    out.push_str(&format!("[sources.{id}]\n"));
    out.push_str(&format!("type = \"{}\"\n", source.kind.as_str()));
    match source.kind {
        PullSourceKind::AwsS3 => {
            out.push_str(&format!("region = \"${{{env}REGION}}\"\n"));
            out.push_str(&format!("endpoint = \"{AWS_RESIGN_ENDPOINT}\"\n"));
            out.push_str("compression = \"auto\"\n");
            out.push_str("acknowledgements.enabled = true\n");
            header(out, ".auth");
            out.push_str(&format!("access_key_id = \"{INERT_CREDENTIAL}\"\n"));
            out.push_str(&format!("secret_access_key = \"{INERT_CREDENTIAL}\"\n"));
            header(out, ".sqs");
            out.push_str(&format!("queue_url = \"${{{env}QUEUE_URL}}\"\n"));
            out.push_str("delete_message = true\n");
            // D-I: a batch the edge log rejects must stay on the queue (customer
            // DLQ redrive), never be deleted.
            out.push_str("delete_failed_message = false\n");
            out.push_str(&format!(
                "visibility_timeout_secs = {SQS_VISIBILITY_TIMEOUT_SECS}\n"
            ));
            // P0-2: objects of one receive are processed serially, each
            // waiting for its end-to-end ack; pollers are the parallelism.
            out.push_str(&format!(
                "client_concurrency = {}\n",
                source
                    .sqs_client_concurrency
                    .unwrap_or(DEFAULT_SQS_CLIENT_CONCURRENCY)
            ));
            out.push_str(&format!(
                "max_number_of_messages = {}\n",
                source
                    .sqs_max_number_of_messages
                    .unwrap_or(DEFAULT_SQS_MAX_NUMBER_OF_MESSAGES)
            ));
        }
        PullSourceKind::AwsSqs => {
            out.push_str(&format!("region = \"${{{env}REGION}}\"\n"));
            out.push_str(&format!("endpoint = \"{AWS_RESIGN_ENDPOINT}\"\n"));
            out.push_str(&format!("queue_url = \"${{{env}QUEUE_URL}}\"\n"));
            out.push_str("delete_message = true\n");
            out.push_str(&format!(
                "visibility_timeout_secs = {SQS_VISIBILITY_TIMEOUT_SECS}\n"
            ));
            out.push_str("acknowledgements.enabled = true\n");
            header(out, ".auth");
            out.push_str(&format!("access_key_id = \"{INERT_CREDENTIAL}\"\n"));
            out.push_str(&format!("secret_access_key = \"{INERT_CREDENTIAL}\"\n"));
        }
        PullSourceKind::GcpPubsub => {
            // No credentials: Vector's GCP auth falls back to the metadata
            // server, which the Worker intercepts with a broker-minted token
            // (D-L: 1 h tokens, GCP_PUBSUB_TOKEN_LIFETIME_SECS).
            out.push_str(&format!(
                "# Token: metadata.google.internal handler, {GCP_PUBSUB_TOKEN_LIFETIME_SECS} s tokens (D-L).\n"
            ));
            out.push_str(&format!("project = \"${{{env}GCP_PROJECT}}\"\n"));
            out.push_str(&format!("subscription = \"${{{env}GCP_SUBSCRIPTION}}\"\n"));
            out.push_str(&format!("ack_deadline_secs = {PUBSUB_ACK_DEADLINE_SECS}\n"));
            out.push_str("acknowledgements.enabled = true\n");
        }
        PullSourceKind::AzureEventHubs => {
            // NAN-3604 (DESIGN §5): AMQPS 5671 to the derived namespace FQDN,
            // checkpoints in the customer's own blob container. Coordinates
            // are env (the Worker validates them against the row); no
            // custom_endpoint, connection_string or secret exists here.
            out.push_str(&format!(
                "# Token: entra.internal managed-identity handler ({AZURE_IDENTITY_ENDPOINT}).\n"
            ));
            out.push_str(&format!("namespace = \"${{{env}EH_NAMESPACE}}\"\n"));
            out.push_str(&format!("event_hub_name = \"${{{env}EH_NAME}}\"\n"));
            out.push_str(&format!(
                "consumer_group = \"${{{env}EH_CONSUMER_GROUP}}\"\n"
            ));
            // Only for a partition with no checkpoint yet: point-forward.
            out.push_str(&format!("start_position = \"{AZURE_START_POSITION}\"\n"));
            out.push_str(&format!(
                "checkpoint_interval_secs = {AZURE_CHECKPOINT_INTERVAL_SECS}\n"
            ));
            out.push_str("acknowledgements.enabled = true\n");
            out.push_str("decoding.codec = \"bytes\"\n");
            out.push_str("framing.method = \"bytes\"\n");
            let auth = |out: &mut String| {
                out.push_str(&format!(
                    "azure_credential_kind = \"{AZURE_CREDENTIAL_KIND}\"\n"
                ));
                out.push_str(&format!(
                    "user_assigned_managed_identity_id = \"${{{env}AZURE_CLIENT_ID}}\"\n"
                ));
                out.push_str(&format!(
                    "user_assigned_managed_identity_id_type = \"{AZURE_IDENTITY_ID_TYPE}\"\n"
                ));
            };
            header(out, ".auth");
            auth(out);
            header(out, ".checkpoint_store");
            out.push_str("type = \"azure_blob\"\n");
            out.push_str(&format!(
                "account_name = \"${{{env}CHECKPOINT_ACCOUNT}}\"\n"
            ));
            out.push_str(&format!(
                "container_name = \"${{{env}CHECKPOINT_CONTAINER}}\"\n"
            ));
            header(out, ".checkpoint_store.auth");
            auth(out);
        }
    }
}

/// NAN-3604: point-forward for queues and subscriptions. Neither has an
/// offset nano may move (nano never seeks a Pub/Sub subscription), so a
/// backlog the customer's queue or subscription already held when the source
/// was created (SQS: up to 14 days, Pub/Sub: up to 7) would be consumed in one
/// burst. The filter drops (acks/deletes, never ingests) an event whose send
/// time is older than the cutoff minus the grace. `aws_sqs`: Vector's
/// `.timestamp` (the SQS `SentTimestamp`). `gcp_pubsub`: `.timestamp` (the
/// message's `publish_time`). `aws_s3`: [`S3_EVENT_TIME_FIELD`] (the S3
/// notification's `eventTime`), falling back to `.timestamp` (the object's
/// `LastModified`) only on a Vector without that field; Vector's `aws_s3`
/// source never carries the SQS `SentTimestamp`, so there is no such rung.
/// An event with no usable time passes (fail-open: never skip what cannot be
/// dated). The drop is `intentional="true"`, so it is the skipped-backlog
/// count and never loss. A filter condition is read-only, so the stamp (the
/// next transform) deletes [`S3_EVENT_TIME_FIELD`].
fn render_backlog_filter(out: &mut String, source: &PullSource) {
    let (Some(component), Some(cutoff)) =
        (backlog_component(source), source.backlog_cutoff_unix_ms)
    else {
        return;
    };
    let threshold = cutoff.saturating_sub(BACKLOG_CUTOFF_GRACE_MS);
    out.push_str(&format!(
        "\n# NAN-3604: point-forward. Skip (ack, never ingest) what the queue/subscription held\n\
         # before the source existed (created {cutoff} ms, grace {BACKLOG_CUTOFF_GRACE_MS} ms).\n\
         [transforms.{component}]\n\
         type = \"filter\"\n\
         inputs = [\"{}\"]\n\
         condition = '''\n\
         {}\
         nano_pull_sent_error != null || to_unix_timestamp(nano_pull_sent, unit: \"milliseconds\") >= {threshold}\n\
         '''\n",
        source_component(source),
        backlog_send_time_vrl(source.kind),
    ));
}

/// The backlog filter's dating step: binds `nano_pull_sent` and
/// `nano_pull_sent_error` (null when the time is usable). `aws_s3` prefers
/// the notification's `eventTime` ([`S3_EVENT_TIME_FIELD`]). `timestamp()`
/// accepts only a timestamp value, so an object user-metadata string of that
/// name (a Vector without the field) is never trusted: `.timestamp` decides.
fn backlog_send_time_vrl(kind: PullSourceKind) -> String {
    match kind {
        PullSourceKind::AwsS3 => format!(
            "nano_pull_sent, nano_pull_sent_error = timestamp(.{S3_EVENT_TIME_FIELD})\n\
             if nano_pull_sent_error != null {{\n\
             \x20 nano_pull_sent, nano_pull_sent_error = timestamp(.timestamp)\n\
             }}\n"
        ),
        _ => "nano_pull_sent, nano_pull_sent_error = timestamp(.timestamp)\n".to_string(),
    }
}

/// The literal behind [`AZURE_RECORDS_CAP`], so the stamp's `concat!` VRL
/// and the Rust constant cannot drift apart.
macro_rules! azure_records_cap {
    () => {
        10000
    };
}

/// NAN-3604: the most records one Event Hubs message explodes into. A batch
/// over the cap keeps its first `AZURE_RECORDS_CAP` records and adds ONE
/// truncation event (`nano_pull_error = "azure_records_truncated"`, the
/// original count, the cap), so one message fans out to at most cap + 1
/// events, the same bound as a batch exactly at the cap.
pub const AZURE_RECORDS_CAP: usize = azure_records_cap!();

/// The stamp: identity comes from the server row, never from the event
/// (§R4). It has no abort or error path, so it can never drop an event (a
/// drop would count as delivered and delete the customer's message).
///
/// NAN-3712: a runtime source's stamp (`provider`) also sets
/// `%nano_pull_provider`, which the source-agnostic origin stamp
/// ([`pull_origin_runtime_vrl`]) reads; without it the stamp is byte-identical.
fn render_stamp(out: &mut String, source: &PullSource, tenant_uuid: Uuid, provider: bool) {
    let slug = &source.slug;
    out.push_str(&format!(
        "\n[transforms.{}]\ntype = \"remap\"\ninputs = [\"{}\"]\nsource = '''\n",
        stamp_component(source),
        backlog_component(source).unwrap_or_else(|| source_component(source))
    ));
    // NAN-3604: the backlog filter dated the event by the notification's
    // eventTime; the lane's parsers never see the field.
    if source.kind == PullSourceKind::AwsS3 && backlog_component(source).is_some() {
        out.push_str(&format!("del(.{S3_EVENT_TIME_FIELD})\n"));
    }
    out.push_str(&format!(".source_type = \"{slug}\"\n"));
    out.push_str(&format!("%source_type = \"{slug}\"\n"));
    out.push_str(&format!("%tenant_id = \"{}\"\n", tenant_uuid.hyphenated()));
    out.push_str(&format!(
        "%nano_credential_id = \"{}\"\n",
        credential_id(source)
    ));
    if provider {
        out.push_str(&format!(
            "%nano_pull_provider = \"{}\"\n",
            pull_origin_provider(source.kind).0
        ));
    }
    out.push_str(".auth_status = \"authenticated\"\n");
    out.push_str(&format!(
        ".content_format = \"nano_pull_{}\"\n",
        source.kind.as_str()
    ));
    out.push_str(".routing_timestamp = now()\n");
    out.push_str("if !exists(.message) { .message = \"\" }\n");
    out.push_str("if !is_object(.metadata) { .metadata = {} }\n");
    out.push_str(".metadata.forwarded_via = \"pull\"\n");
    if let Some(envelope) = envelope(source) {
        out.push_str(envelope.vrl());
    }
    out.push_str("'''\n");
}

/// NAN-3371 (P0-2): a delivery envelope the platform stamp unwraps before the
/// lane, because it is a property of how the cloud delivers objects, not of
/// parsing: push paths (HEC, Firehose) already deliver one record per event,
/// and the lane keeps taking exactly one record in `.message`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullEnvelope {
    /// A CloudTrail log file, `{"Records": [...]}`: one event per record.
    /// Digest files (`.../CloudTrail-Digest/...`, no `Records`) emit nothing:
    /// they are not events, and their message is acked like a filtered event.
    CloudTrailRecords,
    /// NAN-3604: an Event Hubs message. Azure Monitor (diagnostic settings,
    /// Activity Log, Entra ID logs) delivers a batch per message,
    /// `{"records": [...]}`; a top-level JSON array is a batch too. One event
    /// per element, each keeping the message's source fields
    /// (`event_hub_name`, `partition_id`, `offset`, `sequence_number`,
    /// `enqueued_time`, ...) and the stamp's metadata, but NOT the message's
    /// application `properties` (unbounded, customer-set; copying them into
    /// every record would multiply them by the batch size); a string element is
    /// kept as is, any other element becomes its JSON. Other top-level keys
    /// next to `records` are DROPPED (only the records are events). An empty
    /// batch emits nothing (the message is acked like a filtered event). A
    /// single record object, an object without a `records` array, or a body
    /// that is not JSON passes through as ONE event: never dropped, the
    /// lane decides (`azure_monitor` keeps it as an OCSF Base Event), with
    /// its `properties`. A batch over [`AZURE_RECORDS_CAP`] keeps its first
    /// `AZURE_RECORDS_CAP` records plus one truncation event (see the const).
    AzureRecords,
}

impl PullEnvelope {
    /// Appended to the stamp, after the identity lines, so every record
    /// carries them. Infallible and abort-free: an object that is not a
    /// CloudTrail envelope passes through as one event (the lane decides),
    /// and the file body is removed before the copies, so a large file is not
    /// held once per record.
    pub fn vrl(self) -> &'static str {
        match self {
            Self::CloudTrailRecords => concat!(
                "# NAN-3371: CloudTrail file -> one event per record; digest files are not events.\n",
                "nano_pull_object = string(.object) ?? \"\"\n",
                "if starts_with(nano_pull_object, \"CloudTrail-Digest/\") || contains(nano_pull_object, \"/CloudTrail-Digest/\") {\n",
                "  . = []\n",
                "} else {\n",
                "  nano_pull_parsed, nano_pull_error = parse_json(string(.message) ?? \"\")\n",
                "  nano_pull_is_envelope = false\n",
                "  nano_pull_records = []\n",
                "  if nano_pull_error == null && is_object(nano_pull_parsed) {\n",
                "    nano_pull_envelope = object(nano_pull_parsed) ?? {}\n",
                "    if is_array(nano_pull_envelope.Records) {\n",
                "      nano_pull_is_envelope = true\n",
                "      nano_pull_records = array(nano_pull_envelope.Records) ?? []\n",
                "    }\n",
                "  }\n",
                "  if nano_pull_is_envelope {\n",
                "    del(.message)\n",
                "    nano_pull_event = .\n",
                "    . = map_values(nano_pull_records) -> |nano_pull_record| {\n",
                "      nano_pull_one = nano_pull_event\n",
                "      nano_pull_one.message = encode_json(nano_pull_record)\n",
                "      nano_pull_one\n",
                "    }\n",
                "  }\n",
                "}\n",
            ),
            Self::AzureRecords => concat!(
                "# NAN-3604: Event Hubs message -> one event per record ({\"records\": [...]} or a bare array).\n",
                "nano_pull_parsed, nano_pull_error = parse_json(string(.message) ?? \"\")\n",
                "nano_pull_is_batch = false\n",
                "nano_pull_records = []\n",
                "if nano_pull_error == null {\n",
                "  if is_array(nano_pull_parsed) {\n",
                "    nano_pull_is_batch = true\n",
                "    nano_pull_records = array(nano_pull_parsed) ?? []\n",
                "  } else if is_object(nano_pull_parsed) {\n",
                "    nano_pull_envelope = object(nano_pull_parsed) ?? {}\n",
                "    if is_array(nano_pull_envelope.records) {\n",
                "      nano_pull_is_batch = true\n",
                "      nano_pull_records = array(nano_pull_envelope.records) ?? []\n",
                "    }\n",
                "  }\n",
                "}\n",
                "if nano_pull_is_batch {\n",
                "  del(.message)\n",
                "  del(.properties)\n",
                "  nano_pull_total = length(nano_pull_records)\n",
                "  nano_pull_truncated = nano_pull_total > ", azure_records_cap!(), "\n",
                "  if nano_pull_truncated {\n",
                "    nano_pull_records = slice(nano_pull_records, 0, ", azure_records_cap!(), ") ?? []\n",
                "  }\n",
                "  nano_pull_event = .\n",
                "  nano_pull_out = map_values(nano_pull_records) -> |nano_pull_record| {\n",
                "    nano_pull_one = nano_pull_event\n",
                "    nano_pull_one.message = string(nano_pull_record) ?? encode_json(nano_pull_record)\n",
                "    nano_pull_one\n",
                "  }\n",
                "  if nano_pull_truncated {\n",
                "    nano_pull_marker = nano_pull_event\n",
                "    nano_pull_marker.nano_pull_error = \"azure_records_truncated\"\n",
                "    nano_pull_marker.nano_pull_records_total = nano_pull_total\n",
                "    nano_pull_marker.nano_pull_records_cap = ", azure_records_cap!(), "\n",
                "    nano_pull_marker.message = encode_json({\"nano_pull_error\": \"azure_records_truncated\", \"records_total\": nano_pull_total, \"records_kept\": ", azure_records_cap!(), "})\n",
                "    nano_pull_out = push(nano_pull_out, nano_pull_marker)\n",
                "  }\n",
                "  . = nano_pull_out\n",
                "}\n",
            ),
        }
    }
}

/// The envelope a pull source's objects arrive in, by kind and lane slug.
pub fn envelope(source: &PullSource) -> Option<PullEnvelope> {
    match (source.kind, source.slug.as_str()) {
        (PullSourceKind::AwsS3, CLOUDTRAIL_SLUG) => Some(PullEnvelope::CloudTrailRecords),
        // Every Event Hubs lane (azure_monitor, azure_activity, ...): the
        // batch is how Event Hubs delivers, not a property of the log.
        (PullSourceKind::AzureEventHubs, _) => Some(PullEnvelope::AzureRecords),
        _ => None,
    }
}

/// The loss-accounting probe ([`LOSS_FENCE_CONTRACT`]): only the counters the
/// fence needs, on their own small exporter.
///
/// NAN-3712: a runtime bundle (`runtime`) also exports Vector's own reload
/// counters (`reloaded_total`, `component_errors_total{error_code="reload"|"config_load"}`,
/// both without a component), so the pull DO can confirm an applied config
/// from the same small scrape.
fn render_loss_probe(out: &mut String, capture: bool, runtime: bool) {
    // NAN-3623: a capture render keeps the tap's discards (its sampling and
    // its best-effort sink) out of the loss exporter; every other clause
    // already names only pull, exporter or Bronze components.
    let (open, close) = if capture {
        (
            format!("tap = starts_with(component, \"{CAPTURE_COMPONENT_PREFIX}\")\n(!tap && "),
            ")",
        )
    } else {
        (String::new(), "")
    };
    let reload = if runtime {
        "\x20 (component == \"\" && (.name == \"reloaded_total\" ||\n\
         \x20   (.name == \"component_errors_total\" && includes([\"reload\", \"config_load\"], .tags.error_code)))) ||\n"
    } else {
        ""
    };
    out.push_str(&format!(
        "\n# NAN-3371/NAN-3372 loss accounting ({LOSS_FENCE_CONTRACT}): a discard the source\n\
         # keeps for the customer's DLQ is not loss. The pull Worker scrapes only this\n\
         # exporter (scrapes are metered egress); the rule is pull.rs LOSS_FENCE_CONTRACT.\n\
         [sources.{PULL_LOSS_SOURCE}]\n\
         type = \"internal_metrics\"\n\
         scrape_interval_secs = 10\n\
         namespace = \"nanosiem_pull\"\n\
         \n\
         [transforms.{PULL_LOSS_SELECT}]\n\
         type = \"filter\"\n\
         inputs = [\"{PULL_LOSS_SOURCE}\"]\n\
         condition = '''\n\
         component = to_string(.tags.component_id) ?? \"\"\n\
         pull = starts_with(component, \"{PULL_COMPONENT_PREFIX}\") && !starts_with(component, \"{PULL_COMPONENT_PREFIX}loss_\")\n\
         {open}.name == \"component_discarded_events_total\"{close} ||\n\
         \x20 (component == \"{PULL_LOSS_SOURCE}\" && .name == \"component_sent_events_total\") ||\n\
         {reload}\
         \x20 (pull && includes([\"component_received_events_total\", \"component_errors_total\",\n\
         \x20   \"sqs_message_received_messages_total\", \"sqs_message_delete_succeeded_total\",\n\
         \x20   \"sqs_message_delete_failed_total\", \"sqs_message_processing_succeeded_total\"], .name)) ||\n\
         \x20 (component == \"{BRONZE_SINK}\" && includes([\"component_sent_events_total\", \"component_errors_total\"], .name))\n\
         '''\n\
         \n\
         [sinks.{PULL_LOSS_EXPORTER}]\n\
         type = \"prometheus_exporter\"\n\
         inputs = [\"{PULL_LOSS_SELECT}\"]\n\
         address = \"{PULL_LOSS_EXPORTER_ADDRESS}\"\n\
         default_namespace = \"nanosiem_pull\"\n"
    ));
}

/// NAN-3623: the opt-in Nano Pipe capture tap, after every stamp and beside
/// the lane (`source_router`), rendered only for a tenant whose Worker renders
/// `worker.pipe_capture` (build.json `pull_capture`).
///
/// ```text
/// http_client GET capture.internal/v1/status (every 2 s)
///   └▶ nano_pipe_capture_active ─▶ memory table nano_pipe_capture_sessions (slug -> 1, TTL 6 s)
/// stamps ─▶ nano_pipe_capture_select (filter: lane has a session; one hash-map lookup)
///        ─▶ nano_pipe_capture_throttle (20 events/s per lane)
///        ─▶ nano_pipe_capture_shape ({ message, source_type } only; > 32 KiB = truncated marker)
///        ─▶ memory table nano_pipe_capture_buffer (≤ 1 MiB; ACKS every event as delivered)
///             └▶ source nano_pipe_capture_export (fresh events, NO finalizers, every 1 s)
///                ─▶ http sink POST capture.internal/v1/observe (no retries, drop_newest)
/// ```
///
/// The buffer is load-bearing: the pull sources run end-to-end
/// acknowledgements, so a sink fed straight from the stamps would hold each
/// pulled message's ack on the capture request, and a failed capture request
/// would mark the batch errored (SQS: not deleted, redelivered; measured on
/// the fork image: an acknowledging source answered 500 for every event while
/// a direct capture sink failed, 200 with the buffer). The memory table marks
/// every event it takes `Delivered` and its export source emits new events
/// without finalizers, so nothing the tap does (a slow, failing or absent
/// Worker handler) can delay, fail or drop a pulled event. Its inserts never
/// block (over the byte cap they are rejected) and the sink never
/// back-pressures the export (`when_full = "drop_newest"`). Every component is
/// in the fork image (nano-rs/vector distribution/docker/nano/COMPONENTS:
/// http_client, filter, throttle, remap, memory, http).
///
/// `stamps` are the select's inputs: the stamp ids, or (NAN-3712 runtime
/// bundle) [`PULL_STAMP_GLOB`].
fn render_capture_tap(out: &mut String, stamps: &[String]) {
    let p = CAPTURE_COMPONENT_PREFIX;
    let stamps = stamps
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(", ");
    out.push_str(&format!(
        "\n# NAN-3623 Nano Pipe live capture (opt-in, worker.pipe_capture): sampled pulled\n\
         # events reach the tenant's capture sessions through the tenant-bound\n\
         # {PIPE_CAPTURE_HOST} handler. Decoupled from acknowledgements by the memory-table\n\
         # buffer: capture can never delay, fail or drop a pulled event (pull.rs render_capture_tap).\n\
         [sources.{p}status]\n\
         type = \"http_client\"\n\
         endpoint = \"{CAPTURE_STATUS_URI}\"\n\
         scrape_interval_secs = {CAPTURE_STATUS_INTERVAL_SECS}\n\
         scrape_timeout_secs = 1.5\n\
         decoding.codec = \"json\"\n\
         \n\
         [transforms.{p}active]\n\
         type = \"remap\"\n\
         inputs = [\"{p}status\"]\n\
         source = '''\n\
         . = filter(object(.active) ?? {{}}) -> |nano_capture_slug, nano_capture_on| {{\n\
         \x20 nano_capture_on == 1 && match(nano_capture_slug, r'^[a-z0-9][a-z0-9_-]{{0,99}}$')\n\
         }}\n\
         '''\n\
         \n\
         [enrichment_tables.{p}sessions]\n\
         type = \"memory\"\n\
         inputs = [\"{p}active\"]\n\
         ttl = {CAPTURE_SESSION_TTL_SECS}\n\
         scan_interval = 1\n\
         \n\
         [transforms.{p}select]\n\
         type = \"filter\"\n\
         inputs = [{stamps}]\n\
         condition = '''\n\
         is_object(get_enrichment_table_record(\"{p}sessions\", {{\"key\": string(.source_type) ?? \"\"}}) ?? null)\n\
         '''\n\
         \n\
         [transforms.{p}throttle]\n\
         type = \"throttle\"\n\
         inputs = [\"{p}select\"]\n\
         threshold = {CAPTURE_EVENTS_PER_SEC_PER_LANE}\n\
         window_secs = 1\n\
         key_field = \"{{{{ source_type }}}}\"\n\
         \n\
         [transforms.{p}shape]\n\
         type = \"remap\"\n\
         inputs = [\"{p}throttle\"]\n\
         source = '''\n\
         nano_capture_message = string(.message) ?? encode_json(.message)\n\
         nano_capture_event = {{\"message\": nano_capture_message, \"source_type\": string(.source_type) ?? \"\"}}\n\
         if strlen(nano_capture_message) > {CAPTURE_MAX_MESSAGE_BYTES} {{\n\
         \x20 nano_capture_event = {{\"message\": \"\", \"source_type\": nano_capture_event.source_type, \"truncated\": true}}\n\
         }}\n\
         . = set!({{}}, [uuid_v4()], nano_capture_event)\n\
         '''\n\
         \n\
         [enrichment_tables.{p}buffer]\n\
         type = \"memory\"\n\
         inputs = [\"{p}shape\"]\n\
         ttl = 30\n\
         scan_interval = 5\n\
         max_byte_size = {CAPTURE_BUFFER_MAX_BYTES}\n\
         source_config.source_key = \"{p}export\"\n\
         source_config.export_interval = 1\n\
         source_config.export_batch_size = 200\n\
         source_config.remove_after_export = true\n\
         \n\
         [sinks.{p}observe]\n\
         type = \"http\"\n\
         inputs = [\"{p}export\"]\n\
         uri = \"{CAPTURE_OBSERVE_URI}\"\n\
         method = \"post\"\n\
         encoding.codec = \"json\"\n\
         healthcheck.enabled = false\n\
         batch.max_events = 200\n\
         batch.max_bytes = 262144\n\
         batch.timeout_secs = 1\n\
         request.concurrency = 1\n\
         request.retry_attempts = 0\n\
         request.timeout_secs = 5\n\
         buffer.type = \"memory\"\n\
         buffer.max_events = 400\n\
         buffer.when_full = \"drop_newest\"\n"
    ));
}

/// `05-pull-sources.toml` for `sources` (already validated and sorted).
/// `capture` (NAN-3623) appends the capture tap; without it the file is
/// byte-identical to the render before the tap existed.
pub fn render_pull_sources(tenant_uuid: Uuid, sources: &[PullSource], capture: bool) -> String {
    let mut out = String::from(
        "# NAN-3369: platform pull sources, rendered by the parser-bundle build from the\n\
         # server's pull-source rows. Platform-owned: DO NOT EDIT. Coordinates come from\n\
         # the container env the Worker sets (NANO_PULL_<ID>_*); credentials never do.\n\
         # End-to-end acknowledgements: a source deletes/acks only after the Bronze\n\
         # sink's edge-log commit.\n",
    );
    for source in sources {
        out.push('\n');
        render_source(&mut out, source);
        render_backlog_filter(&mut out, source);
        render_stamp(&mut out, source, tenant_uuid, false);
    }
    if capture {
        let stamps: Vec<String> = sources.iter().map(stamp_component).collect();
        render_capture_tap(&mut out, &stamps);
    }
    render_loss_probe(&mut out, capture, false);
    out
}

/// NAN-3712: `05-pull-sources.toml` of a runtime bundle: the contract marker,
/// the capture tap (`capture`) over [`PULL_STAMP_GLOB`] and the loss probe
/// with the reload counters. No pull source: those are runtime config.
pub fn render_pull_runtime_file(capture: bool) -> String {
    let mut out = String::from(PULL_RUNTIME_MARKER);
    out.push_str(
        "\n# NAN-3712: platform pull plumbing of a runtime-config pull bundle. Platform-owned:\n\
         # DO NOT EDIT. The pull sources are rendered by the pull runtime from the live\n\
         # pull-source rows (pull.rs runtime_template) into dynamic/pull/pull-runtime-sources.toml\n\
         # and reloaded in place; the router and the capture tap take every stamp by glob.\n",
    );
    if capture {
        render_capture_tap(&mut out, &[PULL_STAMP_GLOB.to_string()]);
    }
    render_loss_probe(&mut out, capture, true);
    out
}

// ---------------------------------------------------------------------------
// Line-level TOML blocks
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Owner {
    /// File preamble and global tables (`[api]`, `data_dir`, ...): kept.
    Global,
    Component(String),
    /// The n-th `[[tests]]` of the file (with its sub-tables).
    Test(usize),
}

struct Block<'a> {
    owner: Owner,
    lines: Vec<&'a str>,
}

fn toggles_multiline(line: &str) -> bool {
    (line.matches("'''").count() + line.matches("\"\"\"").count()) % 2 == 1
}

fn is_comment_or_blank(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty() || trimmed.starts_with('#')
}

/// Header name of a table line, outside multi-line strings.
fn header_name(line: &str) -> Option<(bool, String)> {
    let line = line.trim_end_matches(['\n', '\r']).trim_end();
    if let Some(inner) = line.strip_prefix("[[").and_then(|l| l.strip_suffix("]]")) {
        return Some((true, inner.trim().to_string()));
    }
    line.strip_prefix('[')
        .and_then(|l| l.strip_suffix(']'))
        .map(|inner| (false, inner.trim().to_string()))
}

fn split_blocks(text: &str) -> Result<Vec<Block<'_>>, String> {
    let mut blocks = vec![Block {
        owner: Owner::Global,
        lines: Vec::new(),
    }];
    let mut in_multiline = false;
    let mut tests = 0usize;
    for line in text.split_inclusive('\n') {
        if !in_multiline && line.starts_with('[') {
            let (array, name) =
                header_name(line).ok_or_else(|| format!("unparsed table header {line:?}"))?;
            let segments: Vec<&str> = name.split('.').collect();
            let owner = match (array, segments.as_slice()) {
                (true, ["tests"]) => {
                    tests += 1;
                    Owner::Test(tests - 1)
                }
                (_, ["tests", ..]) => match tests {
                    0 => return Err(format!("[{name}] outside a [[tests]] block")),
                    n => Owner::Test(n - 1),
                },
                (false, [kind, id, ..]) if matches!(*kind, "sources" | "transforms" | "sinks") => {
                    if !BARE_KEY_RE.is_match(id) {
                        return Err(format!("component key {id:?} is not a bare key"));
                    }
                    Owner::Component(id.to_string())
                }
                (true, _) => return Err(format!("unsupported array table [[{name}]]")),
                _ => Owner::Global,
            };
            // Comments and blank lines right above a header belong to it.
            let previous = blocks.last_mut().expect("at least one block");
            let mut moved = Vec::new();
            while previous
                .lines
                .last()
                .is_some_and(|l| is_comment_or_blank(l))
            {
                moved.push(previous.lines.pop().expect("checked"));
            }
            moved.reverse();
            let same_component =
                previous.owner == owner && matches!(owner, Owner::Component(_) | Owner::Test(_));
            if same_component {
                previous.lines.extend(moved);
                previous.lines.push(line);
            } else {
                moved.push(line);
                blocks.push(Block {
                    owner,
                    lines: moved,
                });
            }
        } else {
            blocks
                .last_mut()
                .expect("at least one block")
                .lines
                .push(line);
        }
        if toggles_multiline(line) {
            in_multiline = !in_multiline;
        }
    }
    if in_multiline {
        return Err("unterminated multi-line string".into());
    }
    Ok(blocks)
}

// ---------------------------------------------------------------------------
// Component graph
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Component {
    kind: &'static str,
    file: String,
    type_: String,
    inputs: Vec<String>,
}

/// One loaded config file: the parsed view (interpolations neutralized; used
/// only to READ types, inputs, routes and tests) and its raw text.
struct ConfigFile {
    table: toml::Table,
}

fn parse_config(path: &str, text: &str) -> Result<ConfigFile, TenantBundleError> {
    // `${VAR}` may stand for a bare value (`force_path_style = ${X:-false}`);
    // any literal makes the file parseable, and nothing read here depends on it.
    let neutral = INTERPOLATION_RE.replace_all(text, "0");
    let table: toml::Table = neutral.parse().map_err(|e: toml::de::Error| {
        base_err(format!("{path} is not valid TOML: {}", e.message()))
    })?;
    Ok(ConfigFile { table })
}

fn string_list(value: Option<&toml::Value>) -> Vec<String> {
    match value {
        Some(toml::Value::String(s)) => vec![s.clone()],
        Some(toml::Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// The component an input reference names (`route.output` -> `route`).
fn referent(input: &str) -> &str {
    input.split('.').next().unwrap_or(input)
}

/// Components a `[[tests]]` entry inserts at or extracts from.
fn test_references(test: &toml::Value) -> Vec<String> {
    let mut refs = Vec::new();
    let Some(test) = test.as_table() else {
        return refs;
    };
    let mut inputs: Vec<&toml::Value> = Vec::new();
    if let Some(input) = test.get("input") {
        inputs.push(input);
    }
    if let Some(toml::Value::Array(items)) = test.get("inputs") {
        inputs.extend(items.iter());
    }
    for input in inputs {
        refs.extend(string_list(input.get("insert_at")));
    }
    if let Some(toml::Value::Array(outputs)) = test.get("outputs") {
        for output in outputs {
            refs.extend(string_list(output.get("extract_from")));
        }
    }
    refs.extend(string_list(test.get("no_outputs_from")));
    refs
}

/// Whether the cell loads `path` as Vector config (the container start copies
/// `sources/parsers` and `sources/configs` into its `dynamic/` config dirs).
fn is_loaded_config(path: &str) -> bool {
    let in_dir = |dir: &str| {
        path.strip_prefix(dir)
            .is_some_and(|rest| !rest.contains('/') && rest.ends_with(".toml"))
    };
    (!path.contains('/') && path.ends_with(".toml"))
        || in_dir("sources/parsers/")
        || in_dir("sources/configs/")
}

// ---------------------------------------------------------------------------
// The filtered base
// ---------------------------------------------------------------------------

/// Derive the pull base from a platform base: keep only what a pull container
/// runs, add the platform pull sources, and leave every surviving platform
/// line byte-identical (only removed lines and `inputs` lists change).
/// `pull` must be non-empty; it is rendered in `source_id` order. `capture`
/// (NAN-3623) adds the Nano Pipe capture tap ([`render_capture_tap`]).
pub fn pull_base(
    base: &BundleTree,
    pull: &[PullSource],
    tenant_uuid: Uuid,
    capture: bool,
) -> Result<BundleTree, TenantBundleError> {
    pull_base_with(base, pull, tenant_uuid, capture, false)
}

/// [`pull_base`], plus (NAN-3653; `build::generate` always sets it and reports `pull_origin`) the pull origin
/// stamp in the lake storage stage ([`stamp_pull_origin`]).
pub fn pull_base_with(
    base: &BundleTree,
    pull: &[PullSource],
    tenant_uuid: Uuid,
    capture: bool,
    origin: bool,
) -> Result<BundleTree, TenantBundleError> {
    filter_pull_base(base, PullSet::Sources { pull, tenant_uuid, origin }, capture)
}

/// NAN-3712: the filtered base of a runtime-config pull bundle
/// ([`PULL_RUNTIME_CONTRACT`]): the same filter as [`pull_base_with`], but no
/// pull source is rendered. `source_router` (and the capture select) take
/// [`PULL_STAMP_GLOB`], the lake storage stage carries the source-agnostic
/// origin stamp ([`pull_origin_runtime_vrl`]) and `05-pull-sources.toml` is
/// [`render_pull_runtime_file`]. Depends on nothing but the platform base and
/// `capture`, so any verifier rederives it.
pub fn pull_runtime_base(base: &BundleTree, capture: bool) -> Result<BundleTree, TenantBundleError> {
    filter_pull_base(base, PullSet::Runtime, capture)
}

/// What a pull base renders: the requested sources (legacy, NAN-3369), or
/// none (NAN-3712 runtime config).
enum PullSet<'a> {
    Sources {
        pull: &'a [PullSource],
        tenant_uuid: Uuid,
        origin: bool,
    },
    Runtime,
}

fn filter_pull_base(
    base: &BundleTree,
    set: PullSet<'_>,
    capture: bool,
) -> Result<BundleTree, TenantBundleError> {
    let (pull, tenant_uuid, origin) = match set {
        PullSet::Sources { pull, tenant_uuid, origin } => {
            if pull.is_empty() {
                return Err(base_err("no pull source to render"));
            }
            (pull, Some(tenant_uuid), origin)
        }
        PullSet::Runtime => (&[][..], None, true),
    };
    let runtime = tenant_uuid.is_none();
    let mut pull: Vec<PullSource> = pull.to_vec();
    pull.sort();
    if pull.windows(2).any(|w| w[0].source_id == w[1].source_id) {
        return Err(base_err("a pull source id is declared twice"));
    }
    if pull.iter().any(|p| !SOURCE_SLUG_RE.is_match(&p.slug)) {
        return Err(base_err("a pull source slug is malformed"));
    }
    if pull.iter().any(|p| !sqs_tuning_is_valid(p)) {
        return Err(base_err(
            "SQS tuning is aws_s3-only, client_concurrency 1-8, max_number_of_messages 1-2",
        ));
    }
    if pull.iter().any(|p| !backlog_cutoff_is_valid(p)) {
        return Err(base_err(BACKLOG_CUTOFF_MESSAGE));
    }
    if base.files.contains_key(PULL_SOURCES_FILE) {
        return Err(base_err(format!(
            "the platform base already has {PULL_SOURCES_FILE}"
        )));
    }

    // -- read the graph ---------------------------------------------------------
    let config_paths: Vec<&String> = base.files.keys().filter(|p| is_loaded_config(p)).collect();
    let mut parsed: BTreeMap<&str, ConfigFile> = BTreeMap::new();
    for path in &config_paths {
        parsed.insert(path.as_str(), parse_config(path, base.text(path)?)?);
    }
    let mut components: BTreeMap<String, Component> = BTreeMap::new();
    for (path, file) in &parsed {
        for kind in ["sources", "transforms", "sinks"] {
            let Some(table) = file.table.get(kind).and_then(toml::Value::as_table) else {
                continue;
            };
            for (id, body) in table {
                if id.starts_with(PULL_COMPONENT_PREFIX)
                    || (capture && id.starts_with(CAPTURE_COMPONENT_PREFIX))
                {
                    return Err(base_err(format!("the platform base already declares {id}")));
                }
                let component = Component {
                    kind,
                    file: path.to_string(),
                    type_: body
                        .get("type")
                        .and_then(toml::Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    inputs: string_list(body.get("inputs")),
                };
                if components.insert(id.clone(), component).is_some() {
                    return Err(base_err(format!("component {id} is declared twice")));
                }
            }
        }
    }
    if capture {
        for file in parsed.values() {
            let tables = file.table.get("enrichment_tables").and_then(toml::Value::as_table);
            if let Some(id) = tables
                .and_then(|t| t.keys().find(|id| id.starts_with(CAPTURE_COMPONENT_PREFIX)))
            {
                return Err(base_err(format!("the platform base already declares {id}")));
            }
        }
    }
    if !components
        .get(SOURCE_ROUTER)
        .is_some_and(|c| c.file == ROUTER_FILE && c.type_ == "route")
    {
        return Err(base_err(
            "the base has no source_router route in the router file",
        ));
    }
    let route_keys: Vec<String> = parsed[ROUTER_FILE]
        .table
        .get("transforms")
        .and_then(|t| t.get(SOURCE_ROUTER))
        .and_then(|r| r.get("route"))
        .and_then(toml::Value::as_table)
        .map(|routes| routes.keys().cloned().collect())
        .unwrap_or_default();
    if !route_keys.iter().any(|k| k == GENERIC_ROUTE) {
        return Err(base_err("source_router has no generic route"));
    }

    // -- decide what goes ----------------------------------------------------------
    let mut removed: BTreeSet<String> = components
        .iter()
        .filter(|(_, c)| c.kind == "sources" && !KEPT_SOURCE_TYPES.contains(&c.type_.as_str()))
        .map(|(id, _)| id.clone())
        .collect();
    let removed_routes: BTreeSet<String> = route_keys
        .iter()
        .filter(|k| k.as_str() != GENERIC_ROUTE)
        .map(|k| format!("{SOURCE_ROUTER}.{k}"))
        .collect();
    let stamps: Vec<String> = if runtime {
        vec![PULL_STAMP_GLOB.to_string()]
    } else {
        pull.iter().map(stamp_component).collect()
    };
    let mut inputs: BTreeMap<String, Vec<String>> = components
        .iter()
        .filter(|(_, c)| c.kind != "sources")
        .map(|(id, c)| (id.clone(), c.inputs.clone()))
        .collect();
    inputs.insert(SOURCE_ROUTER.to_string(), stamps.clone());
    let gone = |input: &str, removed: &BTreeSet<String>| {
        removed.contains(referent(input)) || removed_routes.contains(input)
    };
    loop {
        let newly: Vec<String> = inputs
            .iter()
            .filter(|(id, list)| {
                !removed.contains(*id) && list.iter().all(|input| gone(input, &removed))
            })
            .map(|(id, _)| id.clone())
            .collect();
        if newly.is_empty() {
            break;
        }
        removed.extend(newly);
    }
    for required in [SOURCE_ROUTER, LAKE_PREPARE, BRONZE_SINK] {
        if removed.contains(required) {
            return Err(base_err(format!(
                "{required} does not survive the pull filter"
            )));
        }
    }
    let bronze = &parsed[components[BRONZE_SINK].file.as_str()].table["sinks"][BRONZE_SINK];
    let acked = bronze
        .get("acknowledgements")
        .and_then(|a| a.get("enabled"))
        .and_then(toml::Value::as_bool)
        == Some(true);
    if !acked {
        return Err(base_err(format!(
            "{BRONZE_SINK} must set acknowledgements.enabled = true (source ack only after Bronze commit)"
        )));
    }
    let backoff_cap = bronze
        .get("request")
        .and_then(|r| r.get("retry_max_duration_secs"))
        .and_then(toml::Value::as_integer)
        .unwrap_or(0);
    if backoff_cap < MIN_BRONZE_RETRY_BACKOFF_CAP_SECS {
        return Err(base_err(format!(
            "{BRONZE_SINK} request.retry_max_duration_secs must be at least \
             {MIN_BRONZE_RETRY_BACKOFF_CAP_SECS} (every retry is metered egress)"
        )));
    }
    if components[LAKE_PREPARE].file != LAKE_SINK_FILE {
        return Err(base_err(format!(
            "{LAKE_PREPARE} is not in {LAKE_SINK_FILE}"
        )));
    }

    // -- rewrite the files -------------------------------------------------------
    let mut out = BundleTree::default();
    for path in &config_paths {
        let text = base.text(path)?;
        let tests: Vec<toml::Value> = parsed[path.as_str()]
            .table
            .get("tests")
            .and_then(toml::Value::as_array)
            .cloned()
            .unwrap_or_default();
        let blocks = split_blocks(text).map_err(|e| base_err(format!("{path}: {e}")))?;
        let declared_tests = blocks
            .iter()
            .filter_map(|b| match b.owner {
                Owner::Test(n) => Some(n),
                _ => None,
            })
            .collect::<BTreeSet<usize>>()
            .len();
        if declared_tests != tests.len() {
            return Err(base_err(format!(
                "{path}: [[tests]] blocks do not match the parsed tests"
            )));
        }
        let mut kept = String::with_capacity(text.len());
        let mut has_table = false;
        for block in &blocks {
            let keep = match &block.owner {
                Owner::Global => true,
                Owner::Component(id) => !removed.contains(id),
                Owner::Test(n) => !test_references(&tests[*n])
                    .iter()
                    .any(|r| gone(r, &removed) || !components.contains_key(referent(r))),
            };
            if keep {
                has_table |= block.owner != Owner::Global
                    || block.lines.iter().any(|l| !is_comment_or_blank(l));
                kept.extend(block.lines.iter().copied());
            }
        }
        if !has_table {
            continue;
        }
        // Inputs of surviving components that lost an input.
        for (id, component) in components.iter().filter(|(_, c)| c.file == path.as_str()) {
            if component.kind == "sources" || removed.contains(id) {
                continue;
            }
            let wanted: Vec<String> = if id == SOURCE_ROUTER {
                stamps.clone()
            } else {
                component
                    .inputs
                    .iter()
                    .filter(|input| !gone(input, &removed))
                    .cloned()
                    .collect()
            };
            if wanted != component.inputs {
                kept = rewrite_inputs(&kept, component.kind, id, &wanted)
                    .map_err(|e| base_err(format!("{path}: {e}")))?;
            }
        }
        if path.as_str() == ROUTER_FILE {
            kept =
                remove_routes(&kept, &route_keys).map_err(|e| base_err(format!("{path}: {e}")))?;
        }
        if origin && path.as_str() == LAKE_SINK_FILE {
            let vrl = if runtime {
                pull_origin_runtime_vrl()
            } else {
                pull_origin_vrl(&pull)
            };
            kept = insert_pull_origin(&kept, &vrl).map_err(|e| base_err(format!("{path}: {e}")))?;
        }
        out.put(path, kept.into_bytes());
    }
    let pull_file = match tenant_uuid {
        Some(tenant_uuid) => render_pull_sources(tenant_uuid, &pull, capture),
        None => render_pull_runtime_file(capture),
    };
    out.put(PULL_SOURCES_FILE, pull_file.into_bytes());
    // The container start copies these two directories into its dynamic
    // config dirs (`cp -R sources/configs/. ...`), so they stay even when the
    // filter emptied them.
    for dir in KEPT_DIRS {
        if base.dirs.contains(dir) {
            out.dirs.insert(dir.to_string());
            out.dirs.extend(
                std::path::Path::new(dir)
                    .ancestors()
                    .skip(1)
                    .map(|p| p.to_string_lossy().into_owned())
                    .filter(|p| !p.is_empty()),
            );
        }
    }
    Ok(out)
}

/// NAN-3653: first line of the pull origin stamp (reported as `PullBundleOutput::pull_origin`).
pub const PULL_ORIGIN_MARKER: &str =
    "# NAN-3653: the pull delivery this row came through (OCSF metadata.loggers).";

/// The provider id and display name a pull source kind is shown under: the
/// same vocabulary as `/api/pull-sources` `provider` and the Log Sources
/// origin label, so `| stats count by metadata.loggers.log_provider` and the
/// UI agree.
pub fn pull_origin_provider(kind: PullSourceKind) -> (&'static str, &'static str) {
    match kind {
        PullSourceKind::AwsS3 => ("aws_s3_sqs", "AWS S3 (SQS)"),
        PullSourceKind::AwsSqs => ("aws_sqs", "AWS SQS"),
        PullSourceKind::GcpPubsub => ("gcp_pubsub", "GCP Pub/Sub"),
        PullSourceKind::AzureEventHubs => ("azure_event_hubs", "Azure Event Hubs"),
    }
}

/// The origin stamp's VRL. It reads the identity the platform stamp set from
/// the server row (`%nano_credential_id = "pull:<source_id>"`, never the
/// event) and appends one OCSF Logger to `metadata.loggers`, the attribute
/// OCSF defines for "the devices and logging products between the event
/// source and its eventual destination": `uid` = pull source id,
/// `log_provider` = provider id, `name` = provider display name, `product` =
/// the nano pull container. A lane's own loggers are kept. Infallible and
/// abort-free: an event without a known pull identity is left alone, so the
/// stamp adds no drop path.
pub fn pull_origin_vrl(pull: &[PullSource]) -> String {
    let mut out = String::from(PULL_ORIGIN_MARKER);
    out.push('\n');
    out.push_str("nano_pull_origin = to_string(%nano_credential_id) ?? \"\"\n");
    out.push_str("nano_pull_provider = \"\"\n");
    out.push_str("nano_pull_name = \"\"\n");
    let mut sorted: Vec<&PullSource> = pull.iter().collect();
    sorted.sort();
    for source in sorted {
        let (provider, name) = pull_origin_provider(source.kind);
        out.push_str(&format!(
            "if nano_pull_origin == \"{}\" {{ nano_pull_provider = \"{provider}\"; nano_pull_name = \"{name}\" }}\n",
            credential_id(source)
        ));
    }
    out.push_str(PULL_ORIGIN_LOGGER_VRL);
    out
}

/// The Logger append both origin stamps end with.
const PULL_ORIGIN_LOGGER_VRL: &str = concat!(
    "if nano_pull_provider != \"\" {\n",
    "  nano_pull_loggers = array(.metadata.loggers) ?? []\n",
    "  .metadata.loggers = push(nano_pull_loggers, {\"name\": nano_pull_name, \"uid\": slice(nano_pull_origin, 5) ?? \"\", \"log_provider\": nano_pull_provider, \"product\": {\"name\": \"nano pull\", \"vendor_name\": \"nano\"}})\n",
    "}\n",
);

/// NAN-3712: the origin stamp of a runtime bundle, which names no source: the
/// provider comes from `%nano_pull_provider`, which the runtime source stamp
/// sets from the server row's kind (never from the event), mapped through the
/// fixed provider table of [`pull_origin_provider`]. Only an event with a pull
/// identity (`%nano_credential_id = "pull:<id>"`) and a known provider gets a
/// Logger; anything else is left alone, exactly like [`pull_origin_vrl`].
pub fn pull_origin_runtime_vrl() -> String {
    let mut out = String::from(PULL_ORIGIN_MARKER);
    out.push('\n');
    out.push_str("nano_pull_origin = to_string(%nano_credential_id) ?? \"\"\n");
    out.push_str("nano_pull_provider = \"\"\n");
    out.push_str("nano_pull_name = \"\"\n");
    out.push_str("if starts_with(nano_pull_origin, \"pull:\") {\n");
    out.push_str("  nano_pull_kind = to_string(%nano_pull_provider) ?? \"\"\n");
    for kind in [
        PullSourceKind::AwsS3,
        PullSourceKind::AwsSqs,
        PullSourceKind::GcpPubsub,
        PullSourceKind::AzureEventHubs,
    ] {
        let (provider, name) = pull_origin_provider(kind);
        out.push_str(&format!(
            "  if nano_pull_kind == \"{provider}\" {{ nano_pull_provider = \"{provider}\"; nano_pull_name = \"{name}\" }}\n"
        ));
    }
    out.push_str("}\n");
    out.push_str(PULL_ORIGIN_LOGGER_VRL);
    out
}

/// NAN-3653: insert [`pull_origin_vrl`] into the `ocsf_lake_storage_prepare`
/// VRL of `text` (the lake sink file): just before the bronze row contract
/// when the stage carries it (the row is still the OCSF event there), else at
/// the end of the stage. Exactly one stage, not stamped yet.
pub fn stamp_pull_origin(text: &str, pull: &[PullSource]) -> Result<String, String> {
    insert_pull_origin(text, &pull_origin_vrl(pull))
}

/// [`stamp_pull_origin`] with the given origin VRL (which starts with
/// [`PULL_ORIGIN_MARKER`]).
fn insert_pull_origin(text: &str, vrl: &str) -> Result<String, String> {
    const OPEN: &str = "source = '''\n";
    const CLOSE: &str = "\n'''\n";
    let section = format!("[transforms.{LAKE_PREPARE}]\n");
    if text.matches(section.as_str()).count() != 1 {
        return Err(format!("expected exactly one [transforms.{LAKE_PREPARE}]"));
    }
    if text.contains(PULL_ORIGIN_MARKER) {
        return Err("the lake storage stage already carries the pull origin stamp".into());
    }
    let start = text.find(section.as_str()).expect("counted above");
    let body_start = text[start..]
        .find(OPEN)
        .map(|i| start + i + OPEN.len())
        .ok_or_else(|| format!("{LAKE_PREPARE} has no source block"))?;
    if let Some(next) = text[start + section.len()..].find("\n[").map(|i| start + section.len() + i) {
        if body_start > next {
            return Err(format!("{LAKE_PREPARE} has no source block of its own"));
        }
    }
    let body_end = text[body_start..]
        .find(CLOSE)
        .map(|i| body_start + i)
        .ok_or_else(|| format!("{LAKE_PREPARE} source block is not closed"))?;
    let marker = crate::parsers::lake_bronze_row::LAKE_BRONZE_ROW_MARKER;
    let at = match text[body_start..body_end].find(marker) {
        Some(i) => body_start + i,
        None => body_end + 1,
    };
    Ok(format!("{}{}{}", &text[..at], vrl, &text[at..]))
}

fn rewrite_inputs(text: &str, kind: &str, id: &str, wanted: &[String]) -> Result<String, String> {
    let section = format!("{kind}.{id}");
    let mut found = None;
    let mut current: Option<String> = None;
    let mut in_multiline = false;
    let all: Vec<&str> = text.split_inclusive('\n').collect();
    for (index, raw) in all.iter().enumerate() {
        if !in_multiline && raw.starts_with('[') {
            current = header_name(raw).map(|(_, name)| name);
        }
        if !in_multiline
            && current.as_deref() == Some(section.as_str())
            && raw.starts_with("inputs = [")
        {
            if found.replace(index).is_some() {
                return Err(format!("[{section}] has two inputs lines"));
            }
        }
        if toggles_multiline(raw) {
            in_multiline = !in_multiline;
        }
    }
    let index = found.ok_or_else(|| format!("[{section}] has no single-line inputs list"))?;
    let line = all[index];
    let close = line
        .find(']')
        .ok_or_else(|| format!("[{section}] inputs list is not on one line"))?;
    let tail = &line[close + 1..];
    if !tail.trim().is_empty() && !tail.trim_start().starts_with('#') {
        return Err(format!("[{section}] inputs line has trailing content"));
    }
    let rendered = wanted
        .iter()
        .map(|item| format!("\"{item}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let replacement = format!("inputs = [{rendered}]{tail}");
    let mut owned: Vec<String> = all.iter().map(|l| l.to_string()).collect();
    owned[index] = replacement;
    Ok(owned.concat())
}

/// Drop every route line of `source_router` but `generic`.
fn remove_routes(text: &str, keys: &[String]) -> Result<String, String> {
    let section = format!("transforms.{SOURCE_ROUTER}.route");
    let mut current: Option<String> = None;
    let mut in_multiline = false;
    let mut kept = String::with_capacity(text.len());
    let mut dropped = BTreeSet::new();
    for raw in text.split_inclusive('\n') {
        if !in_multiline && raw.starts_with('[') {
            current = header_name(raw).map(|(_, name)| name);
        }
        let mut drop = false;
        if !in_multiline && current.as_deref() == Some(section.as_str()) {
            if let Some((key, _)) = raw.split_once(" = ") {
                let key = key.trim();
                if key != GENERIC_ROUTE && keys.iter().any(|k| k == key) {
                    if raw.contains("'''") || raw.contains("\"\"\"") {
                        return Err(format!("route {key} spans several lines"));
                    }
                    drop = dropped.insert(key.to_string());
                    if !drop {
                        return Err(format!("route {key} is declared twice"));
                    }
                }
            }
        }
        if !drop {
            kept.push_str(raw);
        }
        if toggles_multiline(raw) {
            in_multiline = !in_multiline;
        }
    }
    let expected: BTreeSet<String> = keys
        .iter()
        .filter(|k| *k != GENERIC_ROUTE)
        .cloned()
        .collect();
    if dropped != expected {
        return Err("a platform route is not a single `key = '...'` line".into());
    }
    Ok(kept)
}

// ---------------------------------------------------------------------------
// The pull bundle
// ---------------------------------------------------------------------------

/// A built pull bundle (not yet packed).
#[derive(Debug, Clone)]
pub struct PullBuild {
    pub base: BundleTree,
    pub candidate: BundleTree,
    pub lane_sources: Vec<String>,
    pub pull_sources: Vec<PullSource>,
}

/// Build the pull bundle for the rendered pull sources: filtered base +
/// overlay of exactly the lane-filter slugs. Verification is the caller's
/// (`verify_against_base_with(.., OverlayProfile::Pull)`).
pub fn build_pull_bundle(
    base: &BundleTree,
    sources: &[TenantSource],
    rendered: &[PullSource],
    tenant_uuid: Uuid,
    capture: bool,
) -> Result<PullBuild, TenantBundleError> {
    build_pull_bundle_with(base, sources, rendered, tenant_uuid, capture, false)
}

/// [`build_pull_bundle`] with the NAN-3653 pull origin stamp (`origin`).
pub fn build_pull_bundle_with(
    base: &BundleTree,
    sources: &[TenantSource],
    rendered: &[PullSource],
    tenant_uuid: Uuid,
    capture: bool,
    origin: bool,
) -> Result<PullBuild, TenantBundleError> {
    let lane_filter: BTreeSet<&str> = rendered.iter().map(|p| p.slug.as_str()).collect();
    let filtered: Vec<TenantSource> = sources
        .iter()
        .filter(|s| lane_filter.contains(s.slug.as_str()))
        .cloned()
        .collect();
    if filtered.len() != lane_filter.len() {
        return Err(base_err("a rendered pull source has no tenant lane"));
    }
    let pull_base = pull_base_with(base, rendered, tenant_uuid, capture, origin)?;
    let (candidate, _) =
        overlay::apply_overlay_with(&pull_base, &filtered, overlay::OverlayProfile::Pull)?;
    let mut pull_sources = rendered.to_vec();
    pull_sources.sort();
    Ok(PullBuild {
        base: pull_base,
        candidate,
        lane_sources: lane_filter.into_iter().map(str::to_string).collect(),
        pull_sources,
    })
}

/// NAN-3712: split the requested runtime lanes into those the tenant has
/// (rendered, sorted) and those it does not (reported as
/// `pull_pending_lanes`; their sources cannot run until the lane is deployed).
pub fn plan_lanes(sources: &[TenantSource], lanes: &[String]) -> (Vec<String>, Vec<String>) {
    let deployed: BTreeSet<&str> = sources.iter().map(|s| s.slug.as_str()).collect();
    let requested: BTreeSet<&String> = lanes.iter().collect();
    requested
        .into_iter()
        .cloned()
        .partition(|slug| deployed.contains(slug.as_str()))
}

/// NAN-3712: build the runtime-config pull bundle ([`PULL_RUNTIME_CONTRACT`]):
/// [`pull_runtime_base`] + overlay of exactly `lanes` (already planned against
/// the tenant's sources). `pull_sources` of the result is empty: the sources
/// are runtime config.
pub fn build_pull_runtime_bundle(
    base: &BundleTree,
    sources: &[TenantSource],
    lanes: &[String],
    capture: bool,
) -> Result<PullBuild, TenantBundleError> {
    if lanes.is_empty() {
        return Err(base_err("no pull lane to render"));
    }
    let lane_filter: BTreeSet<&str> = lanes.iter().map(String::as_str).collect();
    if lane_filter.iter().any(|slug| !SOURCE_SLUG_RE.is_match(slug)) {
        return Err(base_err("a pull lane slug is malformed"));
    }
    let filtered: Vec<TenantSource> = sources
        .iter()
        .filter(|s| lane_filter.contains(s.slug.as_str()))
        .cloned()
        .collect();
    if filtered.len() != lane_filter.len() {
        return Err(base_err("a requested pull lane has no tenant lane"));
    }
    let pull_base = pull_runtime_base(base, capture)?;
    let (candidate, _) =
        overlay::apply_overlay_with(&pull_base, &filtered, overlay::OverlayProfile::Pull)?;
    Ok(PullBuild {
        base: pull_base,
        candidate,
        lane_sources: lane_filter.into_iter().map(str::to_string).collect(),
        pull_sources: Vec::new(),
    })
}

/// NAN-3712: the contract a pull bundle's `05-pull-sources.toml` declares, if
/// it is a runtime-config bundle (`None` for a legacy bundle with rendered
/// sources).
pub fn runtime_contract(pull_sources_file: &str) -> Option<&'static str> {
    let first = pull_sources_file.lines().next()?;
    (first == PULL_RUNTIME_MARKER).then_some(PULL_RUNTIME_CONTRACT)
}

// ---------------------------------------------------------------------------
// NAN-3712: runtime source templates
// ---------------------------------------------------------------------------

/// One runtime source template per (kind, envelope): the exact
/// `render_source + render_backlog_filter + render_stamp` output for a
/// sentinel source, with its identity replaced by tokens. Queue/subscription
/// kinds always carry the backlog filter (every runtime source has its row's
/// `created_at`); Event Hubs never does (`start_position = "latest"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuntimeVariant {
    AwsS3,
    /// `aws_s3` feeding the `aws_cloudtrail` lane: the CloudTrail envelope.
    AwsS3CloudTrail,
    AwsSqs,
    GcpPubsub,
    AzureEventHubs,
}

impl RuntimeVariant {
    pub const ALL: [Self; 5] = [
        Self::AwsS3,
        Self::AwsS3CloudTrail,
        Self::AwsSqs,
        Self::GcpPubsub,
        Self::AzureEventHubs,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AwsS3 => "aws_s3",
            Self::AwsS3CloudTrail => "aws_s3_cloudtrail",
            Self::AwsSqs => "aws_sqs",
            Self::GcpPubsub => "gcp_pubsub",
            Self::AzureEventHubs => "azure_event_hubs",
        }
    }

    pub fn kind(self) -> PullSourceKind {
        match self {
            Self::AwsS3 | Self::AwsS3CloudTrail => PullSourceKind::AwsS3,
            Self::AwsSqs => PullSourceKind::AwsSqs,
            Self::GcpPubsub => PullSourceKind::GcpPubsub,
            Self::AzureEventHubs => PullSourceKind::AzureEventHubs,
        }
    }

    /// The variant a source renders with (the same choice as [`envelope`]).
    pub fn of(kind: PullSourceKind, slug: &str) -> Self {
        match (kind, slug) {
            (PullSourceKind::AwsS3, CLOUDTRAIL_SLUG) => Self::AwsS3CloudTrail,
            (PullSourceKind::AwsS3, _) => Self::AwsS3,
            (PullSourceKind::AwsSqs, _) => Self::AwsSqs,
            (PullSourceKind::GcpPubsub, _) => Self::GcpPubsub,
            (PullSourceKind::AzureEventHubs, _) => Self::AzureEventHubs,
        }
    }

    /// Whether the variant renders the point-forward backlog filter.
    pub fn has_cutoff(self) -> bool {
        self != Self::AzureEventHubs
    }
}

/// Template tokens. Substitution replaces the tokens first, then every
/// `${NANO_PULL_<HEX>_<NAME>}` env reference with the source's (escaped)
/// coordinate value; a template carries nothing else to fill.
pub const TOKEN_SOURCE_ID: &str = "@@SOURCE_ID@@";
pub const TOKEN_SOURCE_HEX: &str = "@@SOURCE_HEX@@";
pub const TOKEN_SOURCE_HEX_UPPER: &str = "@@SOURCE_HEX_UPPER@@";
pub const TOKEN_SLUG: &str = "@@SLUG@@";
pub const TOKEN_CUTOFF_MS: &str = "@@CUTOFF_MS@@";
pub const TOKEN_CUTOFF_THRESHOLD_MS: &str = "@@CUTOFF_THRESHOLD_MS@@";

/// The sentinel a template is rendered from. Its id has hex letters, so the
/// simple and upper-case forms differ, and no digit run of the cutoff.
const SENTINEL_ID: u128 = 0xfedc_ba98_fedc_4ba9_8fed_cba9_8fed_cba9;
const SENTINEL_SLUG: &str = "nano-runtime-template-slug";
const SENTINEL_CUTOFF_MS: u64 = 3_333_333_333_333;

/// The sentinel source of `variant`.
fn sentinel(variant: RuntimeVariant) -> PullSource {
    PullSource {
        source_id: Uuid::from_u128(SENTINEL_ID),
        slug: match variant {
            RuntimeVariant::AwsS3CloudTrail => CLOUDTRAIL_SLUG.to_string(),
            _ => SENTINEL_SLUG.to_string(),
        },
        kind: variant.kind(),
        sqs_client_concurrency: None,
        sqs_max_number_of_messages: None,
        backlog_cutoff_unix_ms: variant.has_cutoff().then_some(SENTINEL_CUTOFF_MS),
    }
}

/// One runtime source block (source, backlog filter, provider stamp): what a
/// substituted template must equal, byte for byte, before interpolation.
fn render_runtime_block(source: &PullSource, tenant_uuid: Uuid) -> String {
    let mut out = String::from("\n");
    render_source(&mut out, source);
    render_backlog_filter(&mut out, source);
    render_stamp(&mut out, source, tenant_uuid, true);
    out
}

/// NAN-3712: the template of `variant` for this tenant (the tenant uuid is
/// baked in; it is the Worker's own tenant). Generated from the one renderer
/// (`render_source`/`render_backlog_filter`/`render_stamp`), so a template
/// can never drift from a legacy render; the Worker renderer emits these for
/// a bundle carrying [`PULL_RUNTIME_CONTRACT`].
pub fn runtime_template(variant: RuntimeVariant, tenant_uuid: Uuid) -> String {
    let source = sentinel(variant);
    let id = source.source_id;
    let threshold = SENTINEL_CUTOFF_MS - BACKLOG_CUTOFF_GRACE_MS;
    let mut text = render_runtime_block(&source, tenant_uuid)
        .replace(&id.hyphenated().to_string(), TOKEN_SOURCE_ID)
        .replace(&id.simple().to_string(), TOKEN_SOURCE_HEX)
        .replace(
            &id.simple().to_string().to_ascii_uppercase(),
            TOKEN_SOURCE_HEX_UPPER,
        )
        .replace(SENTINEL_SLUG, TOKEN_SLUG);
    if variant.has_cutoff() {
        text = text
            .replace(&SENTINEL_CUTOFF_MS.to_string(), TOKEN_CUTOFF_MS)
            .replace(&threshold.to_string(), TOKEN_CUTOFF_THRESHOLD_MS);
    }
    text
}

/// Every variant's template, keyed by [`RuntimeVariant::as_str`].
pub fn runtime_templates(tenant_uuid: Uuid) -> BTreeMap<&'static str, String> {
    RuntimeVariant::ALL
        .into_iter()
        .map(|v| (v.as_str(), runtime_template(v, tenant_uuid)))
        .collect()
}

/// A coordinate value the runtime config may carry: inside a TOML basic
/// string, so no quote, backslash or control character. (`$` is allowed and
/// escaped to `$$`: an Event Hubs consumer group is `$Default`.)
fn runtime_value_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && !value
            .chars()
            .any(|c| c == '"' || c == '\\' || c.is_control())
}

/// NAN-3712: the reference substitution the pull runtime (Worker JS) mirrors.
/// `template` is [`runtime_template`] of `source`'s variant; `env` holds the
/// source's coordinates by their container env name
/// (`NANO_PULL_<HEX>_REGION`, ...: the names [`render_source`] references).
///
/// 1. Tokens: id (hyphenated, simple, upper-case simple), slug, cutoff and
///    its grace threshold. After this pass no `@@` may remain.
/// 2. Every `${NAME}` becomes `env[NAME]` with `$` escaped as `$$` (Vector
///    interpolates the config: `$$` is a literal `$`). A missing or invalid
///    value is refused; nothing else in the text is touched.
///
/// The source itself is checked first: a valid slug and non-nil id, the
/// cutoff present exactly on queue/subscription kinds and in range, no SQS
/// tuning (runtime sources run the defaults), and the variant matching.
pub fn substitute_runtime_template(
    template: &str,
    variant: RuntimeVariant,
    source: &PullSource,
    env: &BTreeMap<String, String>,
) -> Result<String, String> {
    if RuntimeVariant::of(source.kind, &source.slug) != variant {
        return Err("the template variant does not match the source".into());
    }
    if source.source_id.is_nil() || !SOURCE_SLUG_RE.is_match(&source.slug) {
        return Err("a runtime pull source needs a non-nil id and a source slug".into());
    }
    if source.sqs_client_concurrency.is_some() || source.sqs_max_number_of_messages.is_some() {
        return Err("a runtime pull source carries no SQS tuning".into());
    }
    if variant.has_cutoff() != source.backlog_cutoff_unix_ms.is_some()
        || !backlog_cutoff_is_valid(source)
    {
        return Err(BACKLOG_CUTOFF_MESSAGE.into());
    }
    let id = source.source_id;
    let mut text = template
        .replace(TOKEN_SOURCE_ID, &id.hyphenated().to_string())
        .replace(TOKEN_SOURCE_HEX_UPPER, &id.simple().to_string().to_ascii_uppercase())
        .replace(TOKEN_SOURCE_HEX, &id.simple().to_string())
        .replace(TOKEN_SLUG, &source.slug);
    if let Some(cutoff) = source.backlog_cutoff_unix_ms {
        text = text
            .replace(TOKEN_CUTOFF_THRESHOLD_MS, &cutoff.saturating_sub(BACKLOG_CUTOFF_GRACE_MS).to_string())
            .replace(TOKEN_CUTOFF_MS, &cutoff.to_string());
    }
    if text.contains("@@") {
        return Err("the template has an unknown token".into());
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .ok_or("the template has an unterminated ${ reference")?;
        let name = &after[..end];
        let value = env
            .get(name)
            .ok_or_else(|| format!("no value for {name}"))?;
        if !runtime_value_is_valid(value) {
            return Err(format!("{name} is not a valid coordinate value"));
        }
        out.push_str(&value.replace('$', "$$"));
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// NAN-3712: one runtime source block for `source`: its variant's template,
/// substituted. What the Worker renders, in Rust.
pub fn render_runtime_source(
    source: &PullSource,
    tenant_uuid: Uuid,
    env: &BTreeMap<String, String>,
) -> Result<String, String> {
    let variant = RuntimeVariant::of(source.kind, &source.slug);
    substitute_runtime_template(&runtime_template(variant, tenant_uuid), variant, source, env)
}

/// NAN-3712: a sample runtime config with one source per variant (fixed ids
/// and coordinates; the Event Hubs consumer group is `$Default`, so the `$$`
/// escape is exercised). The build's Vector stage loads it beside the runtime
/// bundle (`vector validate`), so every template is proven valid against this
/// exact bundle and Vector binary.
pub fn render_runtime_sample(tenant_uuid: Uuid) -> String {
    let mut out = String::from(
        "# NAN-3712: sample runtime pull config (one source per template variant), loaded\n\
         # only by the build's vector validate of the runtime pull bundle.\n",
    );
    for (n, variant) in RuntimeVariant::ALL.into_iter().enumerate() {
        let source = sample_source(variant, n as u128 + 1);
        let block = render_runtime_source(&source, tenant_uuid, &sample_env(&source))
            .expect("sample sources and coordinates are valid");
        out.push_str(&block);
    }
    out
}

fn sample_source(variant: RuntimeVariant, n: u128) -> PullSource {
    PullSource {
        source_id: Uuid::from_u128(0x5a3b_1e00_0000_4000_8000_0000_0000_0000 + n),
        slug: match variant {
            RuntimeVariant::AwsS3CloudTrail => CLOUDTRAIL_SLUG.to_string(),
            _ => "sample_lane".to_string(),
        },
        kind: variant.kind(),
        sqs_client_concurrency: None,
        sqs_max_number_of_messages: None,
        backlog_cutoff_unix_ms: variant.has_cutoff().then_some(1_760_000_000_000),
    }
}

/// Sample coordinates for every env name a source references.
fn sample_env(source: &PullSource) -> BTreeMap<String, String> {
    let prefix = env_prefix(source);
    [
        ("REGION", "us-east-1"),
        ("QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123456789012/nano-sample"),
        ("GCP_PROJECT", "nano-sample"),
        ("GCP_SUBSCRIPTION", "nano-sample-sub"),
        ("EH_NAMESPACE", "nano-sample.servicebus.windows.net"),
        ("EH_NAME", "nano-sample"),
        ("EH_CONSUMER_GROUP", "$Default"),
        ("AZURE_CLIENT_ID", "00000000-0000-4000-8000-000000000001"),
        ("CHECKPOINT_ACCOUNT", "nanosample"),
        ("CHECKPOINT_CONTAINER", "nano-checkpoints"),
    ]
    .into_iter()
    .map(|(name, value)| (format!("{prefix}{name}"), value.to_string()))
    .collect()
}

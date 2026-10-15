//! The baseline builder's artifact sources must be a SUPERSET of the ingest
//! stamper's.
//!
//! NAN-2361: they had drifted. The stamper
//! (`enrichment.rs::artifact_candidates`) read `url.hostname`,
//! `query.hostname` and `actor.process.file.hashes`; the builder
//! (`prevalence_build.rs`) ingested none of them. The consequence is not a
//! missing row somewhere -- it is that every DNS-query domain and every
//! actor-process hash was stamped `is_new: true` at ingest and could then
//! NEVER enter a baseline to stop being new.
//!
//! An artifact that is permanently novel is noise, and novelty is exactly the
//! signal an analyst is asked to act on. A drift here is silent: nothing
//! errors, the chart simply lies forever about a whole class of artifact.
//!
//! Direction matters. The builder may legitimately ingest MORE than the
//! stamper (`src_endpoint.hostname` / `dst_endpoint.hostname` are baselined
//! without being stamped, which only makes baselines richer). The reverse --
//! stamping a path the builder cannot baseline -- is the broken direction.
//!
//! Run with:
//!   cargo test -p nanosiem-lake-worker --test nan2361_prevalence_source_parity

use nanosiem_lake_worker::prevalence_build::derivative_compatibility_contract;

/// Every artifact path the ingest stamper can emit.
///
/// Mirrored from `enrichment.rs::artifact_candidates`. Kept as a literal rather
/// than imported so that changing the stamper without considering the builder
/// fails HERE, with this explanation, instead of silently agreeing with itself.
const STAMPER_ARTIFACT_PATHS: &[&str] = &[
    "src_endpoint.ip",
    "dst_endpoint.ip",
    "file.hashes.value",
    "process.file.hashes.value",
    "actor.process.file.hashes.value",
    "url.hostname",
    "query.hostname",
    "http_request.url.hostname",
];

fn builder_source_fields() -> Vec<String> {
    derivative_compatibility_contract()["source_fields"]
        .as_array()
        .expect("source_fields must be an array")
        .iter()
        .map(|v| v.as_str().expect("source field must be a string").to_string())
        .collect()
}

#[test]
fn builder_baselines_every_path_the_stamper_can_stamp() {
    let builder = builder_source_fields();
    let missing: Vec<&str> = STAMPER_ARTIFACT_PATHS
        .iter()
        .copied()
        .filter(|path| !builder.iter().any(|f| f == path))
        .collect();
    assert!(
        missing.is_empty(),
        "the stamper emits artifact paths the baseline builder never ingests: {missing:?}\n\
         Artifacts on these paths are stamped `is_new: true` at ingest and can never \
         enter a baseline to stop being new -- permanently novel, permanently noise.\n\
         Add them to the extraction SQL AND to `source_fields` in \
         prevalence_build.rs::derivative_compatibility_contract."
    );
}

/// `source_fields` is content-addressed into the derivative contract sha, so it
/// must actually describe what the SQL reads -- otherwise derivatives built
/// before a source was added are treated as compatible when they are blind to
/// it.
#[test]
fn contract_declares_the_host_identity_and_time_inputs() {
    let builder = builder_source_fields();
    for required in ["time", "metadata.log_source", "device.hostname"] {
        assert!(
            builder.iter().any(|f| f == required),
            "contract omits {required}, which the extraction SQL reads"
        );
    }
}

/// The builder may ingest more than the stamper; this documents the asymmetry
/// so a future reader does not "tidy" the lists into equality.
#[test]
fn builder_may_baseline_paths_the_stamper_does_not_stamp() {
    let builder = builder_source_fields();
    let extra: Vec<&String> = builder
        .iter()
        .filter(|f| {
            !STAMPER_ARTIFACT_PATHS.contains(&f.as_str())
                && !matches!(f.as_str(), "time" | "metadata.log_source" | "device.hostname")
        })
        .collect();
    // Not an assertion about the exact set -- just that this direction is legal
    // and currently exercised (src/dst_endpoint.hostname).
    assert!(
        !extra.is_empty(),
        "expected the builder to baseline at least one path the stamper does not emit"
    );
}

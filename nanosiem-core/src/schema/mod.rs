// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pluggable schema abstraction (`SchemaProfile`) — OCSF Phase 1 (NAN-1244).
//!
//! Today the entire stack hard-codes "schema == the UDM constants": a build-time
//! `UdmField` enum plus six const arrays in `query::clickhouse_sql_gen`. This
//! module lifts that implicit single schema into an explicit [`SchemaProfile`]
//! trait that the SQL generator, field-stats, detection engine, and frontend
//! will (in later phases) consult by `Arc<dyn SchemaProfile>`.
//!
//! Phase 1 is a **pure addition**: it defines the trait and the [`UdmProfile`]
//! implementation, which *references* the existing canonical data for
//! byte-for-byte parity, but re-points no existing call site. See
//! `OCSF_SCHEMA_SUPPORT_SCOPING.md` §2.2.

mod boot_validation;
pub mod entities;
mod metrics;
mod ocsf;
pub mod ocsf_predicates;
pub mod ocsf_registry;
mod profile;
mod risk;
mod spans;
mod types;
mod udm;

pub use boot_validation::{validate_active_schema_table, SchemaValidationError};
pub use metrics::MetricsProfile;
pub(crate) use metrics::canonicalize_metric_field;
pub use ocsf::{
    event_json_hints_in_type, is_event_json_hint, manifest_event_json_hints,
    refresh_live_event_json_hints, set_live_event_json_hints, with_event_json_hints, OcsfProfile,
    OCSF_BOOKKEEPING_COLUMNS,
};
pub use profile::SchemaProfile;
pub use risk::RiskProfile;
pub use spans::SpansProfile;
pub(crate) use spans::canonicalize_span_field;
pub use types::{
    EnrichmentKind, EnrichmentMode, EntityRole, EntityType, EnumIntMapping, FieldCategory,
    FieldDef, FieldResolution, FieldType, SchemaId,
};
pub use udm::UdmProfile;

use std::sync::Arc;

/// The environment variable that selects the active schema profile at boot
/// (scoping §2.4). `ocsf` (default, NAN-5271) or `udm`.
pub const SCHEMA_PROFILE_ENV: &str = "NANO_SCHEMA_PROFILE";

/// Construct the boxed [`SchemaProfile`] for a [`SchemaId`].
///
/// The single place that maps the selected schema id to its concrete profile
/// implementation, so callers (app boot) never name `UdmProfile`/`OcsfProfile`
/// directly and stay decoupled from the profile set.
pub fn profile_for_id(id: SchemaId) -> Arc<dyn SchemaProfile> {
    match id {
        SchemaId::Udm => Arc::new(UdmProfile::new()),
        SchemaId::Ocsf => Arc::new(OcsfProfile::new()),
        // NAN-1555: per-QUERY dataset profiles, injected by the SQL generator's
        // `with_dataset(...)` — never selected as a tenant log schema.
        SchemaId::Spans => Arc::new(SpansProfile::new()),
        SchemaId::Metrics => Arc::new(MetricsProfile::new()),
        // NAN-1798 P2: the derived accumulated-risk dataset, likewise per-query.
        SchemaId::Risk => Arc::new(RiskProfile::new()),
    }
}

/// Resolve the active profile from the `NANO_SCHEMA_PROFILE` environment
/// variable. Unset/empty or `ocsf` → [`OcsfProfile`] (NAN-5271); `udm` →
/// [`UdmProfile`]. Any other value is an error (fail-fast at boot, NAN-800).
///
/// This reads the process environment and is intended to be called **once** at
/// app boot (in `nanosiem-api` config/state); the resolved `Arc` is then stored
/// and threaded down to the search path. Core code must not scatter env reads.
pub fn active_profile_from_env() -> Result<Arc<dyn SchemaProfile>, String> {
    #[cfg(test)]
    if let Some(id) = TEST_ACTIVE_SCHEMA.with(|cell| cell.get()) {
        return Ok(profile_for_id(id));
    }
    let raw = std::env::var(SCHEMA_PROFILE_ENV).unwrap_or_default();
    let id = SchemaId::from_env_str(&raw)?;
    Ok(profile_for_id(id))
}

#[cfg(test)]
thread_local! {
    static TEST_ACTIVE_SCHEMA: std::cell::Cell<Option<SchemaId>> =
        const { std::cell::Cell::new(None) };
}

/// Test-only: pin the profile [`active_profile_from_env`] resolves on the
/// CURRENT thread until the guard drops. Unit tests that exercise an
/// env-resolving path for one profile use this instead of mutating the
/// process environment, which races every other test (NAN-5271: the unset
/// default moved from UDM to OCSF, so "unset" no longer means UDM).
#[cfg(test)]
#[must_use]
pub(crate) fn pin_active_schema_for_test(id: SchemaId) -> TestActiveSchemaGuard {
    let previous = TEST_ACTIVE_SCHEMA.with(|cell| cell.replace(Some(id)));
    TestActiveSchemaGuard { previous }
}

#[cfg(test)]
pub(crate) struct TestActiveSchemaGuard {
    previous: Option<SchemaId>,
}

#[cfg(test)]
impl Drop for TestActiveSchemaGuard {
    fn drop(&mut self) {
        TEST_ACTIVE_SCHEMA.with(|cell| cell.set(self.previous));
    }
}

/// The active *ingested-events* table name for the env-configured schema profile.
/// Returns `"ocsf_logs"` under OCSF, `"logs"` under UDM (and on any resolution
/// error, so a malformed env never breaks an admin query). For the handful of
/// direct ClickHouse reads of ingested events that live OUTSIDE the SearchService
/// seam — feed health, retention stats, rule coverage — which have no profile
/// threaded. UDM byte-identical (returns `"logs"`, exactly as before). NAN-1241.
pub fn active_logs_table() -> &'static str {
    active_profile_from_env()
        .map(|p| logs_table_for(p.id()))
        .unwrap_or("logs")
}

/// Stable discriminator written into the profile-aware per-source telemetry
/// rollup. The rollup deliberately stores both UDM and OCSF lanes because an
/// OCSF Vector deployment writes both raw tables during the transition; every
/// reader must select exactly the active lane or those events are counted
/// twice.
pub fn log_telemetry_profile_for(id: SchemaId) -> &'static str {
    match id {
        SchemaId::Ocsf => "ocsf",
        // Spans, metrics, and risk are per-query datasets rather than tenant log
        // schemas. Keep this mapping total and aligned with `logs_table_for`.
        SchemaId::Udm | SchemaId::Spans | SchemaId::Metrics | SchemaId::Risk => "udm",
    }
}

/// Env-resolving wrapper for [`log_telemetry_profile_for`].
pub fn active_log_telemetry_profile() -> &'static str {
    active_profile_from_env()
        .map(|p| log_telemetry_profile_for(p.id()))
        .unwrap_or("udm")
}

/// The ingested-events table name for a given schema id. Pure (env-free) so it
/// is unit-testable; `active_logs_table` is the env-resolving wrapper. NAN-1241.
/// This is the READ table — search/detection/maintenance all target it.
pub fn logs_table_for(id: SchemaId) -> &'static str {
    match id {
        SchemaId::Ocsf => "ocsf_logs",
        SchemaId::Udm => "logs",
        // NAN-1555: spans/metrics are per-query datasets, never the tenant log
        // table; these arms are unreachable in practice (no
        // `NANO_SCHEMA_PROFILE=spans|metrics`) but keep the dispatch total.
        SchemaId::Spans => "otel_spans",
        SchemaId::Metrics => "otel_metrics",
        // NAN-1798 P2: the risk dataset is DERIVED from the findings stream in
        // the logs table; unreachable as a tenant schema, kept for totality.
        SchemaId::Risk => "logs",
    }
}

/// The table OCSF/UDM events are INSERTED into — distinct from the read table
/// under OCSF. NAN-1443: OCSF writes land in `ocsf_logs_raw` (ENGINE = Null);
/// the `ocsf_logs_raw_mv` materialized view derives the stored row into
/// `ocsf_logs` (so the full `event` blob is never stored). UDM has no such
/// split — writes and reads are both `logs` (byte-identical).
pub fn ingest_table_for(id: SchemaId) -> &'static str {
    match id {
        SchemaId::Ocsf => "ocsf_logs_raw",
        SchemaId::Udm => "logs",
        // NAN-1555: unreachable as a tenant schema; spans/metrics ingest via their
        // own `otel_*_raw` Null+MV lanes (migrations 138/140), kept for totality.
        SchemaId::Spans => "otel_spans_raw",
        SchemaId::Metrics => "otel_metrics_raw",
        // NAN-1798 P2: risk is derived (no ingest lane of its own); findings
        // ingest through the logs lane. Unreachable as a tenant schema.
        SchemaId::Risk => "logs",
    }
}

/// Env-resolving wrapper for [`ingest_table_for`] (mirrors `active_logs_table`).
pub fn active_ingest_table() -> &'static str {
    active_profile_from_env()
        .map(|p| ingest_table_for(p.id()))
        .unwrap_or("logs")
}

/// The content branch main's NAN-3758 defaulted the first-party repositories
/// to before NAN-3897 moved the OCSF 1.9 content onto `main`. A stored row on
/// it is stale and moves to the profile's channel.
pub const RETIRED_OCSF_CONTENT_BRANCH: &str = "ocsf-1.9";

/// The frozen UDM content channel of `nano-rs/parsers` and `nano-rs/rules`.
pub const LEGACY_UDM_CONTENT_BRANCH: &str = "legacy/clickhouse";

/// The content channel (git branch) of the first-party parser/rule
/// repositories for a schema profile (NAN-4940, 11-03 decision): OCSF installs
/// follow `main` (OCSF 1.9, NAN-3897); UDM installs stay on the frozen
/// `legacy/clickhouse` branch, whose trees still carry UDM content. Mirrors the
/// web `contentBranchFor`.
pub fn content_branch_for(id: SchemaId) -> &'static str {
    match id {
        SchemaId::Ocsf => "main",
        // Spans / metrics / risk are per-query datasets, never a tenant log
        // schema; a deployment's profile is UDM or OCSF.
        SchemaId::Udm | SchemaId::Spans | SchemaId::Metrics | SchemaId::Risk => LEGACY_UDM_CONTENT_BRANCH,
    }
}

/// Whether a stored branch is one of the first-party channels the app itself
/// has ever defaulted to (`main`, `legacy/clickhouse`, the retired `ocsf-1.9`)
/// or unset. Such a row follows the active profile's channel; any other branch
/// is an operator pin or a fork branch and is kept.
pub fn is_known_content_channel(stored: &str) -> bool {
    matches!(
        stored.trim(),
        "" | "main" | LEGACY_UDM_CONTENT_BRANCH | RETIRED_OCSF_CONTENT_BRANCH
    )
}

/// True only for the two first-party content repositories
/// (`github.com/nano-rs/parsers`, `github.com/nano-rs/rules`): optional scheme
/// and `www.`, any case, optional `.git` and trailing slash. Anything with
/// credentials, a port, a query or a fragment is not first-party.
pub fn is_first_party_content_url(raw: &str) -> bool {
    matches!(github_repo_path(raw).as_deref(), Some("nano-rs/parsers" | "nano-rs/rules"))
}

/// The lowercased `owner/repo` a plain `github.com` repository URL names, or
/// `None` for anything else. See [`github_owner_repo`]. NAN-4947: the shared
/// matcher for every first-party catalog (parsers, rules, enterprise
/// playbooks).
pub fn github_repo_path(raw: &str) -> Option<String> {
    github_owner_repo(raw).map(|(owner, repo)| format!("{owner}/{repo}").to_ascii_lowercase())
}

/// The single GitHub repository URL parser (NAN-4947): admission, reconcile
/// and sync all go through it, so a URL that is admitted is exactly the
/// repository that is synced.
///
/// Accepts `http(s)://`, `www.` or a bare `github.com/` prefix, an optional
/// `.git` and trailing slash, any case (returned as written). Exactly two
/// path segments (`owner/repo`). Anything with credentials, a port, a query
/// or a fragment, another host, or a deeper path is `None`.
pub fn github_owner_repo(raw: &str) -> Option<(String, String)> {
    let raw = raw.trim();
    let absolute = if raw.starts_with("github.com/") || raw.starts_with("www.github.com/") {
        format!("https://{raw}")
    } else {
        raw.to_owned()
    };
    let url = url::Url::parse(&absolute).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !matches!(url.host_str(), Some("github.com" | "www.github.com"))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let path = url.path().strip_prefix('/')?;
    let path = path.strip_suffix('/').unwrap_or(path);
    let path = path.strip_suffix(".git").unwrap_or(path);
    let (owner, repo) = path.split_once('/')?;
    let valid = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    (valid(owner) && valid(repo) && repo != "." && repo != "..").then(|| (owner.to_owned(), repo.to_owned()))
}

/// Canonical stored form of a GitHub repository URL:
/// `https://github.com/<owner>/<repo>` (lowercased), or `None` when
/// [`github_owner_repo`] refuses it.
pub fn canonical_github_url(raw: &str) -> Option<String> {
    github_repo_path(raw).map(|path| format!("https://github.com/{path}"))
}

/// Creation default for a repository branch: an explicit branch is kept; an
/// omitted one is the profile's content channel for the first-party
/// repositories and `main` for everything else. Pure; see
/// [`default_content_branch`] for the env-resolving wrapper.
pub fn default_content_branch_for(id: SchemaId, url: &str, requested: Option<&str>) -> String {
    match requested.map(str::trim).filter(|b| !b.is_empty()) {
        Some(branch) => branch.to_owned(),
        None if is_first_party_content_url(url) => content_branch_for(id).to_owned(),
        None => "main".to_owned(),
    }
}

/// Env-resolving wrapper for [`default_content_branch_for`]. On a profile
/// resolution error (boot already fails fast on one) it keeps the pre-NAN-4940
/// `main` default rather than guessing.
pub fn default_content_branch(url: &str, requested: Option<&str>) -> String {
    active_profile_from_env()
        .map(|p| default_content_branch_for(p.id(), url, requested))
        .unwrap_or_else(|_| {
            requested
                .map(str::trim)
                .filter(|b| !b.is_empty())
                .unwrap_or("main")
                .to_owned()
        })
}

/// The log-source-repository subtree to sync for a given schema id. Parser and
/// rule definitions live in parallel trees in the same git repo: the UDM tree
/// (`parsers/`, `rules/`) and a sibling OCSF tree (`parsers-ocsf/`,
/// `rules-ocsf/`). Under OCSF the sync walks the `<base>-ocsf/` sibling so the
/// imported parsers/rules emit the active schema; under UDM the stored path is
/// returned unchanged (byte-identical default). Idempotent — a path already
/// ending in `-ocsf` is returned as-is. Pure (env-free) so it is unit-testable;
/// `active_repo_path` is the env-resolving wrapper. NAN-1266.
pub fn repo_path_for(id: SchemaId, stored: &str) -> String {
    match id {
        // NAN-1555: spans/metrics have no parser/rule repo tree; passthrough like
        // UDM (and NAN-1798 P2: likewise the derived risk dataset).
        SchemaId::Udm | SchemaId::Spans | SchemaId::Metrics | SchemaId::Risk => stored.to_string(),
        SchemaId::Ocsf => {
            let base = stored.trim_end_matches('/');
            // NAN-2361: an EMPTY base has no directory to append `-ocsf` to.
            // This produced the literal path `-ocsf/`, which cannot exist, so
            // the tree walk matched nothing and sync reported SUCCESS with zero
            // rules — the nano-rs/rules layout keeps its tactic trees at the
            // repo root and stores `rules_path` as "".
            //
            // The sibling convention applies per top-level folder in that
            // layout (`execution` → `execution-ocsf`), exactly as
            // `selected_repo_path_for` already documents for selected paths;
            // it is not a property of the base. Returning the base unchanged
            // lets the walk see the root, where that per-folder preference is
            // applied.
            if base.is_empty() {
                return stored.to_string();
            }
            if base.ends_with("-ocsf") {
                stored.to_string()
            } else {
                format!("{base}-ocsf/")
            }
        }
    }
}

/// Pick the OCSF variant of each top-level folder in a ROOT-layout repository.
///
/// Returns `(kept_paths, untranslated_paths)`. For every top-level folder that
/// has an `-ocsf` sibling in the tree, only the sibling's files are kept. A
/// folder with no sibling falls back to its UDM files, reported separately so
/// the caller can flag them `untranslated` rather than importing them as ready
/// (NAN-1387) — a rule written against UDM columns will never fire on OCSF.
///
/// NAN-2361: without this, fixing the empty-base remap alone would import BOTH
/// trees, so every rule would arrive twice — once in the wrong schema.
pub fn select_ocsf_root_layout(paths: &[String]) -> (Vec<String>, std::collections::HashSet<String>) {
    let top = |path: &str| path.split('/').next().unwrap_or("").to_string();

    let ocsf_folders: std::collections::HashSet<String> = paths
        .iter()
        .map(|p| top(p))
        .filter(|folder| folder.ends_with("-ocsf"))
        .collect();

    let mut kept = Vec::new();
    let mut untranslated = std::collections::HashSet::new();
    for path in paths {
        let folder = top(path);
        if folder.ends_with("-ocsf") {
            kept.push(path.clone());
        } else if !ocsf_folders.contains(&format!("{folder}-ocsf")) {
            untranslated.insert(path.clone());
            kept.push(path.clone());
        }
        // else: a sibling exists and already supplied this rule.
    }
    (kept, untranslated)
}

/// The UDM counterpart of [`select_ocsf_root_layout`] (NAN-4940): in a
/// ROOT-layout repository, drop every top-level `-ocsf` folder so a UDM
/// install imports only the UDM trees. The first-party `legacy/clickhouse`
/// rules branch carries both (`execution` and `execution-ocsf`); without this
/// a UDM sync imported every rule twice, once against OCSF fields that never
/// match a UDM row.
pub fn select_udm_root_layout(paths: &[String]) -> Vec<String> {
    paths
        .iter()
        .filter(|p| !p.split('/').next().unwrap_or("").ends_with("-ocsf"))
        .cloned()
        .collect()
}

/// The log-source-repository subtree for the env-configured schema profile.
/// Env-resolving wrapper over [`repo_path_for`]; on any resolution error the
/// stored path is returned unchanged so a malformed env never breaks sync.
/// NAN-1266.
pub fn active_repo_path(stored: &str) -> String {
    active_profile_from_env()
        .map(|p| repo_path_for(p.id(), stored))
        .unwrap_or_else(|_| stored.to_string())
}

/// Remap a folder-picker selected path to its `-ocsf` sibling for a given
/// schema id. Folder-picker paths are built as `<rules_path>/<folder>`, so the
/// sibling lives at `<rules_path>-ocsf/<folder>` when the repository has a
/// non-empty configured base ("rules/credential_access" →
/// "rules-ocsf/credential_access"). When the base is empty (trees at the repo
/// root — the nano-rs/rules layout) or the selected path lies outside the
/// base, the sibling convention applies to the path's first segment instead
/// ("demo" → "demo-ocsf"). Idempotent — a segment already ending in `-ocsf`
/// is returned as-is — and byte-identical under UDM. Pure (env-free) so it is
/// unit-testable; `active_selected_repo_path` is the env-resolving wrapper.
/// NAN-1387.
pub fn selected_repo_path_for(id: SchemaId, stored_base: &str, selected: &str) -> String {
    match id {
        // NAN-1555: spans/metrics have no repo tree; passthrough like UDM
        // (and NAN-1798 P2: likewise the derived risk dataset).
        SchemaId::Udm | SchemaId::Spans | SchemaId::Metrics | SchemaId::Risk => selected.to_string(),
        SchemaId::Ocsf => {
            let base = stored_base.trim_start_matches('/').trim_end_matches('/');
            let sel = selected.trim_start_matches('/').trim_end_matches('/');
            if !base.is_empty() {
                let remapped_base = repo_path_for(SchemaId::Ocsf, base);
                let remapped_base = remapped_base.trim_end_matches('/');
                if sel == base {
                    return remapped_base.to_string();
                }
                if let Some(rest) = sel.strip_prefix(&format!("{base}/")) {
                    return format!("{remapped_base}/{rest}");
                }
            }
            // Empty base (repo-root trees) or a path outside the configured
            // base: remap the first segment to its `-ocsf` sibling.
            let (first, rest) = match sel.split_once('/') {
                Some((first, rest)) => (first, Some(rest)),
                None => (sel, None),
            };
            if first.is_empty() || first.ends_with("-ocsf") {
                return selected.to_string();
            }
            match rest {
                Some(rest) => format!("{first}-ocsf/{rest}"),
                None => format!("{first}-ocsf"),
            }
        }
    }
}

/// The `-ocsf` sibling of a folder-picker selected path for the
/// env-configured schema profile. Env-resolving wrapper over
/// [`selected_repo_path_for`]; on any resolution error the selected path is
/// returned unchanged so a malformed env never breaks sync. NAN-1387.
pub fn active_selected_repo_path(stored_base: &str, selected: &str) -> String {
    active_profile_from_env()
        .map(|p| selected_repo_path_for(p.id(), stored_base, selected))
        .unwrap_or_else(|_| selected.to_string())
}

#[cfg(test)]
#[path = "ocsf_alias_semantics_tests.rs"]
mod ocsf_alias_semantics_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::{
        normalize_field_name, EXPLICIT_COLUMNS, LOWERCASE_NORMALIZED_FIELDS, MATERIALIZED_COLUMNS,
        NUMERIC_UDM_FIELDS, PREWHERE_FIELDS, UUID_FIELDS,
    };
    use crate::udm::fields::UdmField;

    // NAN-1241: the ingested-events table name dispatch used by the direct-CH
    // surfaces outside the SearchService seam (feed health, retention, coverage).
    #[test]
    fn logs_table_for_dispatches_by_profile() {
        assert_eq!(logs_table_for(SchemaId::Udm), "logs");
        assert_eq!(logs_table_for(SchemaId::Ocsf), "ocsf_logs");
    }

    #[test]
    fn log_telemetry_profile_dispatches_by_tenant_schema() {
        assert_eq!(log_telemetry_profile_for(SchemaId::Udm), "udm");
        assert_eq!(log_telemetry_profile_for(SchemaId::Ocsf), "ocsf");
    }

    // NAN-1266: log-source-repository subtree dispatch. UDM returns the stored
    // path unchanged (byte-identical); OCSF walks the sibling `<base>-ocsf/`.
    #[test]
    fn repo_path_for_dispatches_by_profile() {
        // UDM: unchanged
        assert_eq!(repo_path_for(SchemaId::Udm, "parsers/"), "parsers/");
        assert_eq!(repo_path_for(SchemaId::Udm, "rules/"), "rules/");
        // OCSF: sibling tree, with or without a trailing slash on input
        assert_eq!(repo_path_for(SchemaId::Ocsf, "parsers/"), "parsers-ocsf/");
        assert_eq!(repo_path_for(SchemaId::Ocsf, "rules/"), "rules-ocsf/");
        assert_eq!(repo_path_for(SchemaId::Ocsf, "parsers"), "parsers-ocsf/");
        // OCSF: idempotent — an already-OCSF path is left as-is
        assert_eq!(repo_path_for(SchemaId::Ocsf, "parsers-ocsf/"), "parsers-ocsf/");
    }

    // NAN-1387: folder-picker selected-path dispatch. UDM returns the selected
    // path unchanged (byte-identical); OCSF walks the `-ocsf` sibling tree.
    #[test]
    fn selected_repo_path_for_dispatches_by_profile() {
        // UDM: unchanged, regardless of base
        assert_eq!(
            selected_repo_path_for(SchemaId::Udm, "rules/", "rules/credential_access"),
            "rules/credential_access"
        );
        assert_eq!(selected_repo_path_for(SchemaId::Udm, "", "demo"), "demo");

        // OCSF + non-empty base: sibling of the configured base
        assert_eq!(
            selected_repo_path_for(SchemaId::Ocsf, "rules/", "rules/credential_access"),
            "rules-ocsf/credential_access"
        );
        assert_eq!(
            selected_repo_path_for(SchemaId::Ocsf, "rules", "rules/demo/sub"),
            "rules-ocsf/demo/sub"
        );
        // Selecting the base itself
        assert_eq!(
            selected_repo_path_for(SchemaId::Ocsf, "rules/", "rules"),
            "rules-ocsf"
        );
        // Nested base swaps the whole base, not its first segment
        assert_eq!(
            selected_repo_path_for(SchemaId::Ocsf, "detections/rules/", "detections/rules/impact"),
            "detections/rules-ocsf/impact"
        );

        // OCSF + empty base (repo-root trees, the nano-rs/rules layout):
        // first-segment sibling
        assert_eq!(selected_repo_path_for(SchemaId::Ocsf, "", "demo"), "demo-ocsf");
        assert_eq!(
            selected_repo_path_for(SchemaId::Ocsf, "", "credential_access/sub"),
            "credential_access-ocsf/sub"
        );
        // Path outside the configured base falls back to first-segment sibling
        assert_eq!(
            selected_repo_path_for(SchemaId::Ocsf, "rules/", "demo"),
            "demo-ocsf"
        );

        // OCSF: idempotent — an already-OCSF selection is left as-is
        assert_eq!(
            selected_repo_path_for(SchemaId::Ocsf, "", "demo-ocsf"),
            "demo-ocsf"
        );
        assert_eq!(
            selected_repo_path_for(SchemaId::Ocsf, "rules-ocsf/", "rules-ocsf/impact"),
            "rules-ocsf/impact"
        );
    }

    // --- Anti-drift gate: UdmProfile must reproduce every const array exactly ---
    //
    // These assert the profile *references* (not copies) the canonical arrays, so
    // when Phase 2 re-points call sites at the profile, a divergence is impossible
    // to introduce silently.

    #[test]
    fn prewhere_fields_match_const() {
        assert_eq!(UdmProfile::new().prewhere_fields(), PREWHERE_FIELDS);
    }

    #[test]
    fn materialized_columns_match_const() {
        assert_eq!(UdmProfile::new().materialized_columns(), MATERIALIZED_COLUMNS);
    }

    #[test]
    fn explicit_columns_match_const() {
        // resolve() returns ExplicitColumn for exactly the EXPLICIT_COLUMNS set.
        let p = UdmProfile::new();
        for col in EXPLICIT_COLUMNS {
            assert_eq!(
                p.resolve(col),
                FieldResolution::ExplicitColumn((*col).to_string()),
                "explicit column {col} did not resolve to ExplicitColumn",
            );
        }
    }

    #[test]
    fn lowercase_normalized_fields_match_const() {
        let p = UdmProfile::new();
        // Every const member is lowercased-at-ingest per the profile...
        for f in LOWERCASE_NORMALIZED_FIELDS {
            assert!(
                p.is_lowercased_at_ingest(f),
                "{f} should be lowercased-at-ingest",
            );
        }
        // ...and nothing outside the const set is.
        let set: std::collections::HashSet<&str> =
            LOWERCASE_NORMALIZED_FIELDS.iter().copied().collect();
        for col in EXPLICIT_COLUMNS {
            assert_eq!(
                p.is_lowercased_at_ingest(col),
                set.contains(col),
                "is_lowercased_at_ingest disagreed with const for {col}",
            );
        }
    }

    #[test]
    fn numeric_fields_match_const() {
        let p = UdmProfile::new();
        let set: std::collections::HashSet<&str> = NUMERIC_UDM_FIELDS.iter().copied().collect();
        for f in NUMERIC_UDM_FIELDS {
            assert!(p.is_numeric_field(f), "{f} should be numeric");
        }
        // No explicit column outside the const should be flagged numeric.
        for col in EXPLICIT_COLUMNS {
            assert_eq!(
                p.is_numeric_field(col),
                set.contains(col),
                "is_numeric_field disagreed with const for {col}",
            );
        }
    }

    #[test]
    fn uuid_fields_match_const() {
        let p = UdmProfile::new();
        let set: std::collections::HashSet<&str> = UUID_FIELDS.iter().copied().collect();
        for f in UUID_FIELDS {
            assert!(p.is_uuid_field(f), "{f} should be a UUID field");
        }
        for col in EXPLICIT_COLUMNS {
            assert_eq!(
                p.is_uuid_field(col),
                set.contains(col),
                "is_uuid_field disagreed with const for {col}",
            );
        }
    }

    // --- resolve() ≡ is_explicit_column() across the whole field universe ---

    #[test]
    fn resolve_matches_is_explicit_column_for_all_explicit_columns() {
        let p = UdmProfile::new();
        for col in EXPLICIT_COLUMNS {
            // EXPLICIT_COLUMNS are exactly the names crate::query::is_explicit_column
            // returns true for; resolve() must return ExplicitColumn for each.
            assert!(matches!(
                p.resolve(col),
                FieldResolution::ExplicitColumn(_)
            ));
        }
    }

    #[test]
    fn resolve_matches_is_explicit_column_across_all_udm_fields() {
        let p = UdmProfile::new();
        let explicit: std::collections::HashSet<&str> = EXPLICIT_COLUMNS.iter().copied().collect();
        // For every field in the generated UDM universe, resolve()'s ExplicitColumn
        // vs Unknown decision must agree with EXPLICIT_COLUMNS membership.
        for f in UdmField::all() {
            let name = f.column_name();
            let resolved_explicit =
                matches!(p.resolve(name), FieldResolution::ExplicitColumn(_));
            assert_eq!(
                resolved_explicit,
                explicit.contains(name),
                "resolve() disagreed with EXPLICIT_COLUMNS membership for {name}",
            );
        }
    }

    #[test]
    fn resolve_unknown_for_non_field() {
        assert_eq!(
            UdmProfile::new().resolve("definitely_not_a_field_xyz"),
            FieldResolution::Unknown,
        );
    }

    // --- fields() universe parity with the generated enum ---

    #[test]
    fn fields_cover_all_udm_fields() {
        let p = UdmProfile::new();
        let names: std::collections::HashSet<&str> =
            p.fields().iter().map(|f| f.name).collect();
        assert_eq!(p.fields().len(), UdmField::all().len());
        for f in UdmField::all() {
            assert!(
                names.contains(f.column_name()),
                "fields() missing {}",
                f.column_name(),
            );
        }
    }

    #[test]
    fn canonicalize_matches_normalize_field_name() {
        let p = UdmProfile::new();
        // Aliases must rewrite identically to the canonical free fn...
        for f in ["sourcetype", "hostname", "_time", "event_id"] {
            assert_eq!(
                p.canonicalize(f).as_ref(),
                normalize_field_name(f),
                "canonicalize disagreed with normalize_field_name for alias {f}",
            );
        }
        // ...and non-aliased fields pass through unchanged (Borrowed).
        for f in ["src_ip", "user", "definitely_not_a_field_xyz"] {
            let c = p.canonicalize(f);
            assert_eq!(c.as_ref(), normalize_field_name(f));
            assert!(
                matches!(c, std::borrow::Cow::Borrowed(_)),
                "non-aliased field {f} should canonicalize to Borrowed",
            );
        }
    }

    #[test]
    fn is_known_field_accepts_explicit_and_csv_fields() {
        let p = UdmProfile::new();
        assert!(p.is_known_field("src_ip"));
        assert!(p.is_known_field("user"));
        assert!(!p.is_known_field("definitely_not_a_field_xyz"));
    }

    // --- NAN-1425: gated alias authority (mirrors NAN-1422 on the OCSF side) ---

    /// Every `normalize_field_name` alias whose target is an explicit `logs`
    /// column, alias-by-alias. `source_ip` is deliberately absent — pinned typo
    /// case, gate precedence (see `udm_pinned_typo_alias_not_claimed`).
    /// `service_name` is also absent here: its RAW spelling is a generated
    /// `UdmField`, so the profile never re-aliases it (see
    /// `udm_known_raw_spelling_never_realiased`).
    const UDM_ACCEPTED_ALIASES: &[(&str, &str)] = &[
        ("_time", "timestamp"),
        ("sourcetype", "source_type"),
        ("dest_hostname", "dest_host"),
        ("src_hostname", "src_host"),
        ("username", "user"),
        ("destination_ip", "dest_ip"),
        ("src_address", "src_ip"),
        ("dest_address", "dest_ip"),
        ("source_port", "src_port"),
        ("destination_port", "dest_port"),
        ("source_mac", "src_mac"),
        ("destination_mac", "dest_mac"),
        ("process", "command_line"),
        ("parent_process", "parent_command_line"),
        ("uri", "url"),
        ("referer", "http_referrer"),
        ("referrer", "http_referrer"),
        ("useragent", "http_user_agent"),
        ("filename", "file_name"),
        ("filepath", "file_path"),
        ("outcome", "status"),
        ("response_code", "http_status_code"),
        ("http_status", "http_status_code"),
        ("http_response_code", "http_status_code"),
        ("resp_code", "http_status_code"),
        ("request_method", "http_method"),
        ("method", "http_method"),
        ("dns_query", "query"),
        ("dns_response", "answer"),
        ("dns_answer", "answer"),
        ("cloud.provider", "cloud_provider"),
        ("cloud.account.id", "cloud_account_id"),
        ("cloud.account.name", "cloud_account_name"),
        ("cloud.region", "cloud_region"),
        ("cloud.service.name", "cloud_service"),
        ("event_id", "signature_id"),
        ("eventid", "signature_id"),
    ];

    #[test]
    fn udm_accepted_aliases_are_known_and_resolve_to_canonical_column() {
        let p = UdmProfile::new();
        for (alias, target) in UDM_ACCEPTED_ALIASES {
            assert!(
                p.is_known_field(alias),
                "alias {alias} must be a known field (NAN-1425)"
            );
            assert_eq!(
                p.resolve(alias),
                FieldResolution::ExplicitColumn((*target).to_string()),
                "alias {alias} must resolve to its canonical column {target}",
            );
            // …and identically to the canonical spelling, so codegen seams
            // that pass the RAW name (IN-list) land on the same column.
            assert_eq!(
                p.resolve(alias),
                p.resolve(target),
                "alias {alias} and canonical {target} must resolve identically",
            );
        }
    }

    #[test]
    fn udm_pinned_typo_alias_not_claimed() {
        // COLLISION (recorded on NAN-1425): normalize_field_name maps
        // `source_ip` → `src_ip`, but the NAN-1380 G5 typo gate pins
        // `source_ip` as a rejected near-miss ("did you mean src_ip") and that
        // takes precedence — the profile must not claim it as known, and it
        // must keep resolving Unknown.
        let p = UdmProfile::new();
        assert!(!p.is_known_field("source_ip"));
        assert_eq!(p.resolve("source_ip"), FieldResolution::Unknown);
    }

    #[test]
    fn udm_alias_without_explicit_target_does_not_rewrite() {
        // `hostname` → `host` and `destination` → `dest`: targets are not
        // explicit `logs` columns, so the gated alias authority refuses the
        // rewrite (mirrors NAN-1422's `hostname` pin on OCSF) — these names
        // stay exactly as unknown as before and spill to ext raw.
        let p = UdmProfile::new();
        for alias in ["hostname", "destination"] {
            assert!(!p.is_known_field(alias), "{alias} must stay unknown");
            assert_eq!(p.resolve(alias), FieldResolution::Unknown);
        }
    }

    #[test]
    fn udm_known_raw_spelling_never_realiased() {
        // `service_name` is a generated UdmField whose spelling the codegen
        // map rewrites to `cloud_service` — but a real field never re-aliases
        // through the profile: it stays known via its RAW spelling and keeps
        // resolving Unknown (ext spill), exactly the pre-NAN-1425 behavior the
        // anti-drift gates above pin.
        let p = UdmProfile::new();
        assert!(p.is_known_field("service_name"));
        assert_eq!(p.resolve("service_name"), FieldResolution::Unknown);
    }

    #[test]
    fn udm_alias_type_predicates_judge_canonical_target() {
        // The IN-list seam consults is_numeric_field/is_uuid_field with the
        // RAW name; an accepted alias must type like its target or
        // `response_code IN ("200")` would emit `lower(<UInt16 col>)` (CH type
        // error) while the canonical form takes the numeric branch.
        let p = UdmProfile::new();
        for alias in ["response_code", "http_status", "source_port", "destination_port"] {
            assert!(
                p.is_numeric_field(alias),
                "{alias} must inherit its numeric target type"
            );
        }
        // String-targeted aliases stay non-numeric…
        assert!(!p.is_numeric_field("sourcetype"));
        // …pinned/refused aliases keep raw-spelling lookups only.
        assert!(!p.is_numeric_field("source_ip"));
        // No alias targets a UUID column today; the predicate must agree.
        for (alias, _) in UDM_ACCEPTED_ALIASES {
            assert!(!p.is_uuid_field(alias));
        }
    }

    #[test]
    fn udm_alias_sql_is_byte_identical_to_canonical() {
        // End-to-end codegen: the alias form and the canonical form must
        // generate byte-identical SQL under UDM — Eq, IN-list (the seam that
        // passes RAW names to the profile), stats and table positions.
        use crate::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
        let time_range = TimeRange {
            start: "2024-01-01T00:00:00Z".parse().unwrap(),
            end: "2024-01-02T00:00:00Z".parse().unwrap(),
        };
        let generator = ClickHouseSqlGenerator::new();
        let sql_for = |q: &str| -> String {
            let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
            generator
                .generate(&query, &time_range)
                .unwrap_or_else(|e| panic!("generate {q}: {e}"))
        };
        for (alias, target) in UDM_ACCEPTED_ALIASES {
            for (alias_q, canonical_q) in [
                (format!(r#"{alias}="x""#), format!(r#"{target}="x""#)),
                (
                    format!(r#"{alias} IN ("x", "y")"#),
                    format!(r#"{target} IN ("x", "y")"#),
                ),
                (
                    format!("* | stats count() by {alias}"),
                    format!("* | stats count() by {target}"),
                ),
            ] {
                let alias_sql = sql_for(&alias_q);
                let canonical_sql = sql_for(&canonical_q);
                assert_eq!(
                    alias_sql, canonical_sql,
                    "alias {alias} must generate byte-identical SQL to {target} ({alias_q})",
                );
            }
        }
    }

    #[test]
    fn storage_binding_is_udm() {
        let p = UdmProfile::new();
        assert_eq!(p.id(), SchemaId::Udm);
        assert_eq!(p.table_name(), "nanosiem.logs");
        assert_eq!(p.timestamp_expr(), "timestamp");
        assert_eq!(p.enrichment_mode(), EnrichmentMode::Materialized);
    }

    // --- Default-view renames: the projection-fix contract (Phase 3a) ---

    #[test]
    fn udm_default_view_renames_is_action_event_type() {
        // Exactly today's `* EXCEPT (action), action AS event_type` rewrite.
        assert_eq!(
            UdmProfile::new().default_view_renames(),
            &[("action", "event_type")]
        );
    }

    #[test]
    fn ocsf_default_view_renames_is_empty() {
        // OCSF has no `action` column → no rewrite (bare `*`), so a default-view
        // search does not reference a nonexistent UDM column.
        assert!(OcsfProfile::new().default_view_renames().is_empty());
    }

    // --- Canonical entity-extraction order (single source of truth) ---
    //
    // Phase 5 (NAN-1241) unified three drifted hardcoded entity lists (the risk
    // scorer, the event grouper, and the rule risk-entity auto-detector) onto
    // ONE order — `entity_extraction_order()`. This is now the single source of
    // truth for which fields risk attaches to, so pin it: an accidental edit
    // that re-introduces drift / changes risk attribution must be deliberate.

    #[test]
    fn udm_entity_order_is_canonical_and_priority_tiered() {
        let p = UdmProfile::new();
        let order = p.entity_extraction_order();
        let fields: Vec<&str> = order.iter().map(|(_, f)| *f).collect();

        // Priority tiers: IP before host before user before hash (the contract
        // the detection priority tests rely on).
        let pos = |f: &str| fields.iter().position(|x| *x == f).expect(f);
        assert!(pos("src_ip") < pos("src_host"), "IP must outrank host");
        assert!(pos("src_host") < pos("user"), "host must outrank user");
        assert!(pos("user") < pos("file_hash"), "user must outrank hash");

        // The formerly-divergent fields the grouper/auto-detector had dropped are
        // present (the drift the unification fixed).
        for f in ["src_nt_domain", "dest_nt_domain", "metadata.src_ip"] {
            assert!(fields.contains(&f), "canonical order must include {f}");
        }
        // src_ip is the top-priority entity.
        assert_eq!(fields.first(), Some(&"src_ip"));
    }

    // --- Boot-time profile selection (env → SchemaId → profile) ---

    #[test]
    fn schema_id_from_env_str_defaults_and_parses() {
        // NAN-5271: unset/empty now means OCSF; `udm` must be explicit.
        assert_eq!(SchemaId::from_env_str("").unwrap(), SchemaId::Ocsf);
        assert_eq!(SchemaId::from_env_str("  ").unwrap(), SchemaId::Ocsf);
        assert_eq!(SchemaId::from_env_str("udm").unwrap(), SchemaId::Udm);
        assert_eq!(SchemaId::from_env_str("UDM").unwrap(), SchemaId::Udm);
        assert_eq!(SchemaId::from_env_str(" ocsf ").unwrap(), SchemaId::Ocsf);
        assert_eq!(SchemaId::from_env_str("OCSF").unwrap(), SchemaId::Ocsf);
    }

    #[test]
    fn schema_id_from_env_str_rejects_unknown() {
        // Fail-fast, not a silent UDM fallback (NAN-800).
        let err = SchemaId::from_env_str("splunk").unwrap_err();
        assert!(err.contains("invalid NANO_SCHEMA_PROFILE"), "{err}");
    }

    #[test]
    fn profile_for_id_maps_to_concrete_profile() {
        assert_eq!(profile_for_id(SchemaId::Udm).id(), SchemaId::Udm);
        assert_eq!(profile_for_id(SchemaId::Ocsf).id(), SchemaId::Ocsf);
        // And resolves to the right storage table.
        assert_eq!(profile_for_id(SchemaId::Udm).table_name(), "nanosiem.logs");
        assert_eq!(
            profile_for_id(SchemaId::Ocsf).table_name(),
            "nanosiem.ocsf_logs"
        );
    }
}

#[cfg(test)]
mod root_layout_repo_tests {
    use super::*;

    /// NAN-2361: `rules_path=""` produced the literal path `-ocsf/`.
    ///
    /// Nothing in any repository can match that, so the tree walk returned no
    /// files and sync reported SUCCESS with zero rules — silently, for every
    /// root-layout repository (nano-rs/rules keeps its tactic trees at the
    /// repo root). Verified against the live tenant: rule_count 0,
    /// last_sync_status "success".
    #[test]
    fn an_empty_base_is_not_remapped_to_a_path_that_cannot_exist() {
        assert_eq!(repo_path_for(SchemaId::Ocsf, ""), "");
        assert_eq!(repo_path_for(SchemaId::Ocsf, "/"), "/");
        // A real base still gets its sibling.
        assert_eq!(repo_path_for(SchemaId::Ocsf, "rules/"), "rules-ocsf/");
        assert_eq!(repo_path_for(SchemaId::Ocsf, "rules"), "rules-ocsf/");
        // Idempotent, and untouched under UDM.
        assert_eq!(repo_path_for(SchemaId::Ocsf, "rules-ocsf/"), "rules-ocsf/");
        assert_eq!(repo_path_for(SchemaId::Udm, ""), "");
        assert_eq!(repo_path_for(SchemaId::Udm, "rules/"), "rules/");
    }

    #[test]
    fn root_layout_prefers_the_ocsf_sibling_folder() {
        let paths: Vec<String> = [
            "execution/mshta.yml",
            "execution-ocsf/mshta.yml",
            "persistence/run_key.yml",
            "persistence-ocsf/run_key.yml",
            // No sibling: UDM-only tactic.
            "exfiltration/dns_tunnel.yml",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let (kept, untranslated) = select_ocsf_root_layout(&paths);

        assert!(kept.contains(&"execution-ocsf/mshta.yml".to_string()));
        assert!(kept.contains(&"persistence-ocsf/run_key.yml".to_string()));
        // The UDM twins must NOT come along, or every rule imports twice.
        assert!(!kept.contains(&"execution/mshta.yml".to_string()));
        assert!(!kept.contains(&"persistence/run_key.yml".to_string()));

        // A tactic with no OCSF sibling is still imported, but flagged, so it
        // surfaces as untranslated rather than as a rule that will never fire.
        assert!(kept.contains(&"exfiltration/dns_tunnel.yml".to_string()));
        assert!(untranslated.contains("exfiltration/dns_tunnel.yml"));
        assert_eq!(untranslated.len(), 1);
    }

    #[test]
    fn root_layout_with_no_ocsf_folders_keeps_everything_flagged() {
        // The `main` branch shape: no `-ocsf` siblings at all.
        let paths: Vec<String> = ["execution/a.yml", "discovery/b.yml"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (kept, untranslated) = select_ocsf_root_layout(&paths);
        assert_eq!(kept.len(), 2, "nothing should be dropped");
        assert_eq!(untranslated.len(), 2, "all are schema-mismatched");
    }
}

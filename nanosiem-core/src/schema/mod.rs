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
mod ocsf;
mod profile;
mod types;
mod udm;

pub use boot_validation::{validate_active_schema_table, SchemaValidationError};
pub use ocsf::OcsfProfile;
pub use profile::SchemaProfile;
pub use types::{
    EnrichmentKind, EnrichmentMode, EntityRole, EntityType, FieldCategory, FieldDef,
    FieldResolution, FieldType, SchemaId,
};
pub use udm::UdmProfile;

use std::sync::Arc;

/// The environment variable that selects the active schema profile at boot
/// (scoping §2.4). `udm` (default) or `ocsf`.
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
    }
}

/// Resolve the active profile from the `NANO_SCHEMA_PROFILE` environment
/// variable. Unset/empty → [`UdmProfile`] (byte-identical default deployment);
/// `ocsf` → [`OcsfProfile`]. Any other value is an error (fail-fast at boot,
/// NAN-800) rather than a silent UDM fallback against an OCSF table.
///
/// This reads the process environment and is intended to be called **once** at
/// app boot (in `nanosiem-api` config/state); the resolved `Arc` is then stored
/// and threaded down to the search path. Core code must not scatter env reads.
pub fn active_profile_from_env() -> Result<Arc<dyn SchemaProfile>, String> {
    let raw = std::env::var(SCHEMA_PROFILE_ENV).unwrap_or_default();
    let id = SchemaId::from_env_str(&raw)?;
    Ok(profile_for_id(id))
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

/// The ingested-events table name for a given schema id. Pure (env-free) so it
/// is unit-testable; `active_logs_table` is the env-resolving wrapper. NAN-1241.
pub fn logs_table_for(id: SchemaId) -> &'static str {
    match id {
        SchemaId::Ocsf => "ocsf_logs",
        SchemaId::Udm => "logs",
    }
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
        SchemaId::Udm => stored.to_string(),
        SchemaId::Ocsf => {
            let base = stored.trim_end_matches('/');
            if base.ends_with("-ocsf") {
                stored.to_string()
            } else {
                format!("{base}-ocsf/")
            }
        }
    }
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
        assert_eq!(SchemaId::from_env_str("").unwrap(), SchemaId::Udm);
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

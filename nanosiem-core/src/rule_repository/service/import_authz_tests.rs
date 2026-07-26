// SPDX-License-Identifier: AGPL-3.0-or-later

//! Promotion-boundary regression matrix for repository rule import (NAN-2118).
//!
//! `rule_repositories:import` used to be a cheaper route to every detection
//! lifecycle change that `POST /api/rules` and `PUT /api/rules/{id}` gate behind
//! `detections:promote`. These pin the two predicates the preflight and the
//! write path share — including the UPDATE branch, which rewrites `severity`,
//! `schedule_cron` and `lookback_minutes` on a possibly-live rule.

use super::import::*;
use crate::models::{DetectionMode, RuleMode, Severity};
use crate::rule_repository::{ImportRequest, ImportType, NplRule};
use uuid::Uuid;

fn lifecycle(
    mode: RuleMode,
    severity: Severity,
    detection_mode: DetectionMode,
    schedule_cron: Option<&str>,
    lookback_minutes: Option<i32>,
) -> ImportLifecycle {
    ImportLifecycle {
        mode,
        realtime: detection_mode == DetectionMode::RealTime,
        severity,
        detection_mode,
        schedule_cron: schedule_cron.map(str::to_string),
        lookback_minutes,
    }
}

/// A staging, scheduled, medium-severity import on the default schedule.
fn baseline() -> ImportLifecycle {
    lifecycle(
        RuleMode::Staging,
        Severity::Medium,
        DetectionMode::Scheduled,
        Some("*/30 * * * *"),
        Some(60),
    )
}

fn existing(
    severity: Option<&str>,
    schedule_cron: Option<&str>,
    lookback_minutes: Option<i32>,
) -> ExistingImportTarget {
    ExistingImportTarget {
        id: Uuid::now_v7(),
        dataset: None,
        risk_score: None,
        severity: severity.map(str::to_string),
        schedule_cron: schedule_cron.map(str::to_string),
        lookback_minutes,
    }
}

/// The row a `baseline()` import would land on unchanged.
fn matching_existing() -> ExistingImportTarget {
    existing(Some("medium"), Some("*/30 * * * *"), Some(60))
}

fn import_request(mode: Option<&str>, severity: Option<&str>, name: Option<&str>) -> ImportRequest {
    ImportRequest {
        import_type: ImportType::Linked,
        folder: None,
        name: name.map(str::to_string),
        severity: severity.map(str::to_string),
        mode: mode.map(str::to_string),
        custom_npl: None,
        ai_triage_hints: None,
        source_type_mappings: None,
        merge_to_single_source_type: None,
    }
}

fn npl_rule(
    severity: Option<&str>,
    mode: Option<&str>,
    detection_mode: Option<&str>,
    schedule: Option<&str>,
    lookback: Option<&str>,
) -> NplRule {
    NplRule {
        title: "Probe".to_string(),
        description: None,
        author: None,
        severity: severity.map(str::to_string),
        mode: mode.map(str::to_string),
        detection_mode: detection_mode.map(str::to_string),
        schedule: schedule.map(str::to_string),
        lookback: lookback.map(str::to_string),
        mitre_tactics: Vec::new(),
        mitre_techniques: Vec::new(),
        tags: Vec::new(),
        ai_triage_hints: None,
        folder: None,
        query: "source_type=nan2029_no_events".to_string(),
        source_types: Vec::new(),
        required_fields: Vec::new(),
    }
}

// =============================================================================
// CREATE branch — mirrors `requires_promote_for_create`
// =============================================================================

mod create_branch {
    use super::*;

    #[test]
    fn staging_scheduled_needs_no_promote() {
        assert!(!baseline().requires_promote_for_create());
    }

    #[test]
    fn live_or_alerting_needs_promote() {
        for mode in [RuleMode::Live, RuleMode::Alerting] {
            let plan = lifecycle(
                mode,
                Severity::Medium,
                DetectionMode::Scheduled,
                Some("*/30 * * * *"),
                Some(60),
            );
            assert!(
                plan.requires_promote_for_create(),
                "{mode:?} must require detections:promote"
            );
        }
    }

    #[test]
    fn realtime_needs_promote_even_in_staging() {
        // A real-time rule provisions a ClickHouse materialized view at create
        // time, which is why `POST /api/rules` gates it.
        let plan = lifecycle(
            RuleMode::Staging,
            Severity::Medium,
            DetectionMode::RealTime,
            Some("*/30 * * * *"),
            Some(60),
        );
        assert!(plan.requires_promote_for_create());
    }
}

// =============================================================================
// UPDATE branch — mirrors the reachable arms of `requires_promote_for_update`
// =============================================================================

mod update_branch {
    use super::*;

    #[test]
    fn an_identical_re_import_needs_no_promote() {
        // The common case: upstream content changed, lifecycle fields did not.
        // `detections:edit` alone must still be enough.
        assert!(!baseline().requires_promote_for_update(&matching_existing()));
    }

    #[test]
    fn a_schedule_change_needs_promote() {
        let plan = lifecycle(
            RuleMode::Staging,
            Severity::Medium,
            DetectionMode::Scheduled,
            Some("*/1 * * * *"),
            Some(60),
        );
        assert!(plan.requires_promote_for_update(&matching_existing()));
    }

    #[test]
    fn a_severity_downgrade_needs_promote_but_an_upgrade_does_not() {
        let downgrade = lifecycle(
            RuleMode::Staging,
            Severity::Low,
            DetectionMode::Scheduled,
            Some("*/30 * * * *"),
            Some(60),
        );
        assert!(downgrade.requires_promote_for_update(&matching_existing()));

        let upgrade = lifecycle(
            RuleMode::Staging,
            Severity::Critical,
            DetectionMode::Scheduled,
            Some("*/30 * * * *"),
            Some(60),
        );
        assert!(!upgrade.requires_promote_for_update(&matching_existing()));
    }

    #[test]
    fn a_shortened_or_newly_introduced_lookback_needs_promote() {
        let shortened = lifecycle(
            RuleMode::Staging,
            Severity::Medium,
            DetectionMode::Scheduled,
            Some("*/30 * * * *"),
            Some(5),
        );
        assert!(shortened.requires_promote_for_update(&matching_existing()));

        let introduced = lifecycle(
            RuleMode::Staging,
            Severity::Medium,
            DetectionMode::Scheduled,
            Some("*/30 * * * *"),
            Some(60),
        );
        assert!(introduced
            .requires_promote_for_update(&existing(Some("medium"), Some("*/30 * * * *"), None)));
    }

    #[test]
    fn a_lengthened_or_cleared_lookback_needs_no_promote() {
        let lengthened = lifecycle(
            RuleMode::Staging,
            Severity::Medium,
            DetectionMode::Scheduled,
            Some("*/30 * * * *"),
            Some(1440),
        );
        assert!(!lengthened.requires_promote_for_update(&matching_existing()));

        let cleared = lifecycle(
            RuleMode::Staging,
            Severity::Medium,
            DetectionMode::Scheduled,
            Some("*/30 * * * *"),
            None,
        );
        assert!(!cleared.requires_promote_for_update(&matching_existing()));
    }

    /// Fail closed: we cannot prove the change is not a downgrade.
    #[test]
    fn an_unparseable_stored_severity_needs_promote() {
        assert!(baseline()
            .requires_promote_for_update(&existing(Some("¯\\_(ツ)_/¯"), Some("*/30 * * * *"), Some(60))));
        assert!(baseline()
            .requires_promote_for_update(&existing(None, Some("*/30 * * * *"), Some(60))));
    }

    /// The CREATE predicate deliberately does NOT apply to updates: the update
    /// SQL writes neither mode nor detection_mode nor realtime_enabled, so
    /// re-importing an nPL rule whose frontmatter says `mode: live` promotes
    /// nothing. Gating on the requested mode would make a plain content refresh
    /// cost more than the equivalent `PUT /api/rules/{id}`.
    #[test]
    fn a_requested_mode_alone_does_not_make_an_update_a_promotion() {
        for (mode, detection_mode) in [
            (RuleMode::Live, DetectionMode::Scheduled),
            (RuleMode::Alerting, DetectionMode::Scheduled),
            (RuleMode::Staging, DetectionMode::RealTime),
        ] {
            let plan = lifecycle(
                mode,
                Severity::Medium,
                detection_mode,
                Some("*/30 * * * *"),
                Some(60),
            );
            assert!(
                !plan.requires_promote_for_update(&matching_existing()),
                "{mode:?}/{detection_mode:?} writes no lifecycle field on the update branch"
            );
            // ...but the same lifecycle on the CREATE branch still does.
            assert!(plan.requires_promote_for_create());
        }
    }
}

// =============================================================================
// Shared derivations — the anti-drift guarantee between preflight and write
// =============================================================================

mod derivations {
    use super::*;

    #[test]
    fn the_request_overrides_the_rules_own_lifecycle() {
        let npl = npl_rule(
            Some("low"),
            Some("staging"),
            Some("scheduled"),
            Some("0 * * * *"),
            Some("2h"),
        );
        let resolved = ImportLifecycle::resolve(
            &import_request(Some("alerting"), Some("critical"), None),
            Some("high"),
            Some(&npl),
        );
        assert_eq!(resolved.mode, RuleMode::Alerting);
        assert_eq!(resolved.severity, Severity::Critical);
        assert!(resolved.requires_promote_for_create());
    }

    #[test]
    fn the_rules_own_lifecycle_applies_when_the_request_is_silent() {
        let npl = npl_rule(
            Some("high"),
            Some("live"),
            Some("realtime"),
            Some("0 * * * *"),
            Some("2h"),
        );
        let resolved =
            ImportLifecycle::resolve(&import_request(None, None, None), Some("low"), Some(&npl));
        assert_eq!(resolved.mode, RuleMode::Live);
        assert_eq!(resolved.severity, Severity::High);
        assert_eq!(resolved.detection_mode, DetectionMode::RealTime);
        assert!(resolved.realtime);
        assert_eq!(resolved.schedule_cron.as_deref(), Some("0 * * * *"));
        assert_eq!(resolved.lookback_minutes, Some(120));
        assert!(resolved.requires_promote_for_create());
    }

    /// A Sigma repo (no nPL frontmatter) defaults to staging/scheduled, so a
    /// plain import needs only `detections:create`.
    #[test]
    fn a_non_npl_import_defaults_to_staging_scheduled() {
        let resolved = ImportLifecycle::resolve(&import_request(None, None, None), Some("high"), None);
        assert_eq!(resolved.mode, RuleMode::Staging);
        assert_eq!(resolved.severity, Severity::High);
        assert_eq!(resolved.detection_mode, DetectionMode::Scheduled);
        assert_eq!(resolved.schedule_cron.as_deref(), Some("*/30 * * * *"));
        assert_eq!(resolved.lookback_minutes, None);
        assert!(!resolved.requires_promote_for_create());
    }

    #[test]
    fn severity_falls_back_to_medium() {
        let resolved = ImportLifecycle::resolve(&import_request(None, None, None), None, None);
        assert_eq!(resolved.severity, Severity::Medium);
    }

    /// The name is what decides create-vs-update, so the preflight and the write
    /// path must agree on it byte-for-byte.
    #[test]
    fn the_resolved_name_prefers_request_then_title_then_basename() {
        assert_eq!(
            resolve_import_name(Some("My Rule"), Some("Upstream Title"), "a/b/c.yml"),
            "my_rule"
        );
        assert_eq!(
            resolve_import_name(None, Some("Upstream Title"), "a/b/c.yml"),
            "upstream_title"
        );
        // Basename fallback, snake_cased like every other source.
        assert_eq!(resolve_import_name(None, None, "a/b/c.yml"), "c_yml");
        assert_eq!(resolve_import_name(None, None, "c.yml"), "c_yml");
    }

    #[test]
    fn severity_parsing_is_strict_for_authorization_and_lenient_for_storage() {
        assert_eq!(try_parse_severity("critical"), Some(Severity::Critical));
        assert_eq!(try_parse_severity("informational"), Some(Severity::Informational));
        assert_eq!(try_parse_severity("nonsense"), None);
        // The storage path keeps its historic lenient default.
        assert_eq!(parse_severity("nonsense"), Severity::Informational);
    }
}

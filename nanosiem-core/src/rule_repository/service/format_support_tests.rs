//! NAN-5272: Sigma → nPL conversion was retired. A legacy repository row still
//! marked `rule_format = 'sigma'` must be refused with a clear 400, never
//! half-processed or silently synced as nPL.
use super::RuleRepositoryService;
use crate::rule_repository::{RuleRepository, RuleRepositoryError};

fn repo(rule_format: &str) -> RuleRepository {
    RuleRepository {
        id: uuid::Uuid::nil(),
        name: "rules".into(),
        slug: "nano-rs/rules".into(),
        description: None,
        url: "https://github.com/nano-rs/rules".into(),
        branch: "main".into(),
        rules_path: None,
        rule_format: rule_format.into(),
        auto_sync_enabled: true,
        sync_interval_hours: 24,
        last_synced_at: None,
        last_sync_commit: None,
        last_sync_status: None,
        last_sync_error: None,
        rule_count: 0,
        enabled: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        created_by: None,
        selected_paths: None,
    }
}

#[test]
fn native_npl_repositories_are_supported() {
    assert!(RuleRepositoryService::ensure_supported_format(&repo("nanosiem")).is_ok());
}

#[test]
fn sigma_repositories_are_refused_with_a_clear_bad_request() {
    let err = RuleRepositoryService::ensure_supported_format(&repo("sigma")).unwrap_err();
    assert!(matches!(err, RuleRepositoryError::SigmaFormatUnsupported));
    assert_eq!(err.status_code(), 400);
    assert_eq!(
        err.to_string(),
        "Sigma-format repositories are no longer supported; nano rules use nPL/OCSF"
    );
}

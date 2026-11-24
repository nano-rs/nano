// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parser management module

mod credential_repository;
mod ocsf_validation;
#[cfg(test)]
#[path = "ocsf_conformance_tests.rs"]
mod ocsf_conformance_tests;
pub mod gcp_credentials;
#[cfg(test)]
mod gcp_credentials_tests;
mod repository;
mod service;
mod types;
pub mod pipe;
pub mod test_sandbox;
pub mod unrouted;
mod validator;
mod vector_config;
pub mod vrl_diagnostics;
pub mod vrl_functions;
pub mod vrl_guard;
pub mod vrl_safety;
pub mod worker_process;
pub(crate) mod vrl_verdict_memo;
#[cfg(test)]
mod vrl_functions_tests;

pub use credential_repository::{CredentialRepository, CredentialRepositoryError};
pub use ocsf_validation::{
    ocsf_class_grounding, ocsf_class_name, ocsf_validation_version, validate_ocsf_event,
    OcsfValidationDiagnostic, OcsfValidationResult,
};
pub use repository::{
    is_fetch_source_type, list_effective_deployed_parsers, resolve_parser_dispatch_routes,
    ParserRepository, ParserRepositoryError,
};
pub use service::{ParserService, ParserServiceError};
pub use unrouted::{UnroutableParser, SOURCE_CONFIG_NOTE_PREFIX};
pub use types::*;
pub use validator::exec_bounds::{
    MAX_TEST_SAMPLES, MAX_TEST_SAMPLE_BYTES, MAX_TEST_TOTAL_SAMPLE_BYTES, TEST_EXECUTION_BUDGET,
};
pub use validator::{CompiledNormalizer, VrlValidator, VrlValidatorError};
#[cfg(test)]
pub(crate) use validator::validate_enrichment_encoding_contract;
pub use vector_config::{
    current_reload_wait, ActivationOutcome, ReloadWaitStatus, ReloadWatch, DEFAULT_RELOAD_ACK_MAX_SECS,
    base_router_inputs, hec_normalize_present, redact_config_snapshot, PublicationOutcome,
    SnapshotBundle, VectorConfigError, VectorConfigManager, VectorConfigPublicationError,
    VectorConfigPublisher,
};
pub use vector_config::delivery as vector_config_delivery;
pub use vector_config::{
    BackupGeneration as VectorBackupGeneration, DeployReloadFailure as VectorDeployReloadFailure,
    VerifyFailure as VectorVerifyFailure,
    fanin_slots_enabled as vector_config_fanin_slots_enabled,
    is_router_fed as vector_config_is_router_fed,
    local_reload_disabled as vector_config_local_reload_disabled,
};
pub use vector_config::remote_delivery as vector_config_remote_delivery;
pub use vector_config::{
    publication_root as vector_config_publication_root,
    PUBLICATION_DIR_ENV as VECTOR_CONFIG_PUBLICATION_DIR_ENV,
    WORK_DIR_ENV as VECTOR_CONFIG_WORK_DIR_ENV,
};
#[cfg(test)]
pub(crate) use vector_config::test_hooks as vector_config_test_hooks;
pub(crate) use vector_config::config_lock::DeployGuard as VectorDeployGuard;
pub(crate) use vector_config::tree_write as vector_tree_write;
pub use vector_config::hec_route as vector_hec_route;
pub use vrl_functions::vrl_function_catalog;

#[cfg(test)]
#[path = "credential_provider_tests.rs"]
mod credential_provider_tests;

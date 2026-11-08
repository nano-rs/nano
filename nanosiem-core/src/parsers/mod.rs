// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parser management module

mod credential_repository;
pub mod gcp_credentials;
#[cfg(test)]
mod gcp_credentials_tests;
mod repository;
mod service;
mod types;
pub mod pipe;
mod validator;
mod vector_config;
pub mod vrl_diagnostics;
pub mod vrl_functions;
pub mod vrl_guard;
#[cfg(test)]
mod vrl_functions_tests;

pub use credential_repository::{CredentialRepository, CredentialRepositoryError};
pub use repository::{
    list_effective_deployed_parsers, resolve_parser_dispatch_routes,
    resolve_parser_dispatch_routes_lenient, ParserRepository,
    ParserRepositoryError,
};
pub use service::{ParserService, ParserServiceError};
pub use types::*;
pub use validator::{CompiledNormalizer, VrlValidator, VrlValidatorError};
#[cfg(test)]
pub(crate) use validator::validate_enrichment_encoding_contract;
pub use vector_config::{
    ActivationOutcome, ReloadWatch,
    base_router_inputs, hec_normalize_present, redact_config_snapshot, PublicationOutcome,
    SnapshotBundle, VectorConfigError, VectorConfigManager, VectorConfigPublicationError,
    VectorConfigPublisher,
};
pub use vector_config::delivery as vector_config_delivery;
#[cfg(test)]
pub(crate) use vector_config::test_hooks as vector_config_test_hooks;
pub(crate) use vector_config::config_lock::DeployGuard as VectorDeployGuard;
pub use vector_config::hec_route as vector_hec_route;
pub use vrl_functions::vrl_function_catalog;

#[cfg(test)]
#[path = "credential_provider_tests.rs"]
mod credential_provider_tests;

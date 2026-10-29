// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parser management module

mod credential_repository;
pub mod ingest_shaping;
pub mod landing_ocsf;
pub mod lake_bronze_row;
pub mod pipe;
mod ocsf_validation;
mod repository;
mod service;
pub mod tenant_bundle;
mod types;
mod validator;
mod vector_config;
pub mod vrl_guard;
pub mod vrl_diagnostics;
pub mod vrl_functions;

/// Names and signatures from the pinned, security-filtered VRL stdlib.
pub const VRL_FUNCTION_CATALOG: &str = include_str!(concat!(env!("OUT_DIR"), "/vrl-functions.txt"));

pub use credential_repository::{CredentialRepository, CredentialRepositoryError};
pub use ocsf_validation::{
    is_known_ocsf_class, ocsf_attribute_leaf, validate_ocsf_event, OcsfAttributeLeaf, OcsfValidationDiagnostic,
    OcsfValidationResult, OCSF_VALIDATION_VERSION,
};
pub use repository::{
    list_effective_deployed_parsers, resolve_parser_dispatch_routes, ParserRepository,
    ParserRepositoryError, WaitingParser,
};
pub use service::{ParserService, ParserServiceError};
pub use types::*;
#[cfg(test)]
pub(crate) use validator::validate_enrichment_encoding_contract;
pub use validator::{CompiledNormalizer, VrlValidator, VrlValidatorError};
pub use vector_config::delivery as vector_config_delivery;
pub use vector_config::{
    apply_hec_route_fallback, base_router_inputs, hec_normalize_present, redact_config_snapshot,
    ParserConfigOptions, PublicationOutcome, SnapshotBundle, VectorConfigError,
    VectorConfigManager, VectorConfigPublicationError, VectorConfigPublisher, HEC_ROUTE,
};

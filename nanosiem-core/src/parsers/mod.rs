// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parser management module

mod credential_repository;
mod repository;
mod service;
mod types;
mod validator;
mod vector_config;

pub use credential_repository::{CredentialRepository, CredentialRepositoryError};
pub use repository::{
    list_effective_deployed_parsers, resolve_parser_dispatch_routes, ParserRepository,
    ParserRepositoryError,
};
pub use service::{ParserService, ParserServiceError};
pub use types::*;
pub use validator::{VrlValidator, VrlValidatorError};
pub use vector_config::{
    base_router_inputs, hec_normalize_present, redact_config_snapshot, PublicationOutcome,
    SnapshotBundle, VectorConfigError, VectorConfigManager, VectorConfigPublicationError,
    VectorConfigPublisher,
};
pub use vector_config::delivery as vector_config_delivery;

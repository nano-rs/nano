// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parser management module

mod auto_detect;
mod credential_repository;
mod repository;
mod service;
mod types;
mod validator;
mod vector_config;

pub use auto_detect::{
    AutoDetectError, AutoDetectResult, AutoDetector, DetectionMatch, PatternMatchDetail,
    DEFAULT_CONFIDENCE_THRESHOLD,
};
pub use credential_repository::{CredentialRepository, CredentialRepositoryError};
pub use repository::{
    resolve_parser_dispatch_routes, DetectionPatternRepository, ParserLibraryRepository,
    ParserRepository, ParserRepositoryError,
};
pub use service::{ParserService, ParserServiceError};
pub use types::*;
pub use validator::{VrlValidator, VrlValidatorError};
pub use vector_config::{
    base_router_inputs, hec_normalize_present, redact_config_snapshot, VectorConfigError,
    VectorConfigManager,
};

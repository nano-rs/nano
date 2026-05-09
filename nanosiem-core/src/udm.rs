// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unified Data Model (UDM) types and field normalization
//!
//! This module provides:
//! - Standard UDM field definitions for normalized log data
//! - Field normalization for mapping source-specific fields to UDM
//! - Default mappings for common log formats (syslog, JSON, CEF, LEEF)
//! - Field value validation and type coercion
//!
//! Requirements: 2.1-2.9, 3.1-3.5, 9.1-9.5

pub mod csv_parser;
pub mod fields;
pub mod normalizer;
pub mod validation;

// Re-export field types
pub use fields::{UdmDataType, UdmField, UdmFieldCategory, UdmFieldParseError};

// Re-export normalizer types
pub use normalizer::{
    apply_transform, create_cef_mapping, create_json_mapping, create_leef_mapping,
    create_syslog_mapping, get_nested_value, DefaultFieldNormalizer, FieldMapping, FieldNormalizer,
    NormalizationError, NormalizedLog, TransformFn, UdmFieldMapping,
};

// Re-export validation types
pub use validation::{validate_field_value, ValidatedValue, ValidationError, ValidationResult};

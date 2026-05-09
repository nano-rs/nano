// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query validation helpers for detection rules
//!
//! This module provides validation functions for NQL queries, including:
//! - Checking for aggregations and joins (for real-time detection rules)
//! - Validating field names against the UDM schema
//! - Suggesting similar field names for typos
//! - Query cost analysis and warnings (query cost analysis)
//!
//! # Examples
//!
//! ```
//! use nanosiem_core::query::{parse_query, validate_query_fields, validate_field_name};
//!
//! // Validate a single field name
//! match validate_field_name("src_ip") {
//!     Ok(field) => println!("Valid field: {}", field),
//!     Err(e) => println!("Invalid field: {}", e),
//! }
//!
//! // Validate all fields in a query
//! let query = parse_query("src_ip=192.168.1.1 AND dest_port=80").unwrap();
//! let errors = validate_query_fields(&query);
//! if errors.is_empty() {
//!     println!("Query is valid!");
//! } else {
//!     for error in errors {
//!         println!("Error: {}", error);
//!     }
//! }
//! ```

mod cost_analysis;
mod derived_fields;
mod field_validation;
mod query_checks;

pub use cost_analysis::{analyze_query_cost, QueryCostAnalysis, QueryWarning, WarningSeverity};
pub use derived_fields::collect_derived_fields;
pub use field_validation::{
    suggest_similar_fields, validate_field_name, validate_field_name_format, validate_query_fields,
    FieldValidationError,
};
pub use query_checks::{
    contains_aggregation, contains_join, is_aggregation_command, pre_aggregation_subquery,
};

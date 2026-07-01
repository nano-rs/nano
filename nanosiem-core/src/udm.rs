// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unified Data Model (UDM) types and field normalization
//!
//! This module provides:
//! - Standard UDM field definitions for normalized log data
//!
//! Requirements: 2.1-2.9, 9.1-9.5

pub mod csv_parser;
pub mod fields;

// Re-export field types
pub use fields::{UdmDataType, UdmField, UdmFieldCategory, UdmFieldParseError};

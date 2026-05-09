// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query Library Module
//!
//! Provides a library of example queries to help users learn the query language
//! and discover useful patterns for security analysis.

pub mod repository;
pub mod types;

pub use repository::QueryLibraryRepository;
pub use types::*;

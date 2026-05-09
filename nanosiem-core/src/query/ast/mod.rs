// SPDX-License-Identifier: AGPL-3.0-or-later

//! Abstract Syntax Tree types for piped query language
//!
//! This module defines the AST representation for NanoSIEM's piped query syntax.
//! The grammar supports:
//! - Keyword searches with BM25 ranking
//! - Field filters with various comparators
//! - Piped commands: stats, where, sort, head, tail, timechart, table

mod aggregation;
mod commands;
pub(crate) mod eval;
mod lateral;
mod prevalence;
pub(crate) mod types;

pub use aggregation::*;
pub use commands::*;
pub use eval::*;
pub use lateral::*;
pub use prevalence::*;
pub use types::*;

#[cfg(test)]
mod tests;

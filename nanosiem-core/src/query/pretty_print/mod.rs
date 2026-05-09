// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pretty-printer for converting AST back to piped query syntax
//!
//! This module provides the `PrettyPrint` trait for converting query AST
//! nodes back into their string representation.

mod command;
mod expressions;
mod helpers;
mod search_expr;
#[cfg(any())]
mod tests;

use super::ast::*;

/// Trait for pretty-printing AST nodes to query string
pub trait PrettyPrint {
    /// Convert the AST node to a query string
    fn pretty_print(&self) -> String;
}

impl PrettyPrint for Query {
    fn pretty_print(&self) -> String {
        match self {
            Query::Search(expr) => expr.pretty_print(),
            Query::Piped { source, command } => {
                format!("{} | {}", source.pretty_print(), command.pretty_print())
            }
        }
    }
}

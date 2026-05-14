// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log parsing + ClickHouse row mapping
//!
//! The in-process ingestion service was removed when ingestion was moved to
//! Vector → ClickHouse direct writes. The types here are still used by:
//! - `nanosiem-core::audit` to write audit events into the `logs` table
//! - `nanosiem-enterprise::cases::audit` to write case audit events
//! - `nanosiem-core/fuzz` to fuzz the log parser

mod parser;
mod row;

pub use parser::{LogParser, ParsedLog, ParserError};
pub use row::ClickHouseLogRow;

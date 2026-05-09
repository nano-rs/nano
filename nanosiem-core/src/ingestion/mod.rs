// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log Ingestion Service
//!
//! This module provides the log ingestion service for NanoSIEM.
//! It receives logs from Vector (or other sources), applies field normalization,
//! and stores them in ClickHouse (logs) or PostgreSQL (legacy mode).
//!
//! Requirements: 1.1, 1.3, 2.6, 3.1, 3.2, 3.3, 3.4, 3.5

mod parser;
mod service;

pub use parser::{LogParser, ParsedLog, ParserError};
pub use service::{
    ClickHouseLogRow, IngestionConfig, IngestionError, IngestionService, IngestionStats,
};

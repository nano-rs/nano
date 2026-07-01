// SPDX-License-Identifier: AGPL-3.0-or-later

//! Upload Module
//!
//! Provides file upload capabilities for log ingestion and lookup table creation.
//! Supports CSV, JSON, and NDJSON file formats.
//!
//! Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 5.1, 5.2, 7.4

pub mod parser;
pub mod repository;
pub mod service;
pub mod types;

pub use parser::{FileFormat, FileParser, ParseError, ParseResult, ParsedRecord, ParserConfig};
pub use repository::{UploadRepository, UploadRepositoryError};
pub use service::{UploadError, UploadService, DEFAULT_PREVIEW_ROWS, MAX_FILE_SIZE};
pub use types::{
    ColumnInfo, ColumnType, LookupMode, PreviewResult, UploadDestination, UploadFilter,
    UploadRecord, UploadRequest, UploadResult, UploadStatus,
};

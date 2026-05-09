// SPDX-License-Identifier: AGPL-3.0-or-later

//! Feed Management Module
//!
//! Provides functionality for defining and managing log sourcetypes (feeds).
//! Feeds allow categorizing logs based on ingest labels, patterns, or field values.

mod repository;
mod service;
mod types;

pub use repository::{FeedRepository, FeedRepositoryError};
pub use service::*;
pub use types::*;

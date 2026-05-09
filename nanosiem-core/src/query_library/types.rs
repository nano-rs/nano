// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query Library Types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A query in the library
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LibraryQuery {
    pub id: i32,
    pub name: String,
    pub description: String,
    pub query: String,
    pub category: String,
    pub tags: Vec<String>,
    pub difficulty: QueryDifficulty,
    pub use_case: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_builtin: bool,
}

/// Difficulty level for queries
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum QueryDifficulty {
    Beginner,
    Intermediate,
    Advanced,
}

impl std::fmt::Display for QueryDifficulty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryDifficulty::Beginner => write!(f, "beginner"),
            QueryDifficulty::Intermediate => write!(f, "intermediate"),
            QueryDifficulty::Advanced => write!(f, "advanced"),
        }
    }
}

impl std::str::FromStr for QueryDifficulty {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "beginner" => Ok(QueryDifficulty::Beginner),
            "intermediate" => Ok(QueryDifficulty::Intermediate),
            "advanced" => Ok(QueryDifficulty::Advanced),
            _ => Err(format!("Unknown difficulty: {}", s)),
        }
    }
}

/// Request to create a new query in the library
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewLibraryQuery {
    pub name: String,
    pub description: String,
    pub query: String,
    pub category: String,
    pub tags: Vec<String>,
    pub difficulty: QueryDifficulty,
    pub use_case: Option<String>,
}

/// Filter options for querying the library
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LibraryFilter {
    pub category: Option<String>,
    pub difficulty: Option<QueryDifficulty>,
    pub use_case: Option<String>,
    pub tag: Option<String>,
    pub search: Option<String>,
    pub builtin_only: Option<bool>,
}

/// Category with count
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CategoryCount {
    pub category: String,
    pub count: i64,
}

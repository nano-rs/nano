// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prevalence-related AST types
//!
//! This module defines types for prevalence filtering and enrichment in the query AST,
//! including prevalence fields, operators, thresholds, time windows, and conditions.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Fields that can be used in prevalence filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrevalenceField {
    /// Hash prevalence (host count)
    HashPrevalence,
    /// Domain prevalence (host count)
    DomainPrevalence,
    /// Hash first seen timestamp
    HashFirstSeen,
    /// Domain first seen timestamp
    DomainFirstSeen,
}

impl PrevalenceField {
    /// Returns the string representation of the field
    pub fn as_str(&self) -> &'static str {
        match self {
            PrevalenceField::HashPrevalence => "hash_prevalence",
            PrevalenceField::DomainPrevalence => "domain_prevalence",
            PrevalenceField::HashFirstSeen => "hash_first_seen",
            PrevalenceField::DomainFirstSeen => "domain_first_seen",
        }
    }

    /// Check if this field is a prevalence count field
    pub fn is_count_field(&self) -> bool {
        matches!(
            self,
            PrevalenceField::HashPrevalence | PrevalenceField::DomainPrevalence
        )
    }

    /// Check if this field is a timestamp field
    pub fn is_timestamp_field(&self) -> bool {
        matches!(
            self,
            PrevalenceField::HashFirstSeen | PrevalenceField::DomainFirstSeen
        )
    }
}

/// Comparison operators for prevalence filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrevalenceOperator {
    /// Less than (<)
    Lt,
    /// Less than or equal (<=)
    Lte,
    /// Greater than (>)
    Gt,
    /// Greater than or equal (>=)
    Gte,
    /// Equal (=)
    Eq,
    /// Not equal (!=)
    Ne,
}

impl PrevalenceOperator {
    /// Returns the string representation of the operator
    pub fn as_str(&self) -> &'static str {
        match self {
            PrevalenceOperator::Lt => "<",
            PrevalenceOperator::Lte => "<=",
            PrevalenceOperator::Gt => ">",
            PrevalenceOperator::Gte => ">=",
            PrevalenceOperator::Eq => "=",
            PrevalenceOperator::Ne => "!=",
        }
    }
}

/// Threshold values for prevalence filtering
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PrevalenceThreshold {
    /// Count threshold (for prevalence count fields)
    Count(u64),
    /// Duration threshold (for first_seen comparisons, e.g., "now() - 24h")
    Duration(Duration),
}

/// Time window for prevalence calculations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PrevalenceTimeWindow {
    /// Last 1 hour
    OneHour,
    /// Last 24 hours
    TwentyFourHours,
    /// Last 7 days
    SevenDays,
    /// Last 30 days (default - aligns with ingest-time prevalence columns)
    #[default]
    ThirtyDays,
}

impl PrevalenceTimeWindow {
    /// Get the number of hours in this time window
    pub fn hours(&self) -> i64 {
        match self {
            PrevalenceTimeWindow::OneHour => 1,
            PrevalenceTimeWindow::TwentyFourHours => 24,
            PrevalenceTimeWindow::SevenDays => 168,
            PrevalenceTimeWindow::ThirtyDays => 720,
        }
    }

    /// Parse a time window from a string (e.g., "1h", "24h", "7d", "30d")
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "1h" => Some(PrevalenceTimeWindow::OneHour),
            "24h" => Some(PrevalenceTimeWindow::TwentyFourHours),
            "7d" => Some(PrevalenceTimeWindow::SevenDays),
            "30d" => Some(PrevalenceTimeWindow::ThirtyDays),
            _ => None,
        }
    }

    /// Returns the string representation of the time window
    pub fn as_str(&self) -> &'static str {
        match self {
            PrevalenceTimeWindow::OneHour => "1h",
            PrevalenceTimeWindow::TwentyFourHours => "24h",
            PrevalenceTimeWindow::SevenDays => "7d",
            PrevalenceTimeWindow::ThirtyDays => "30d",
        }
    }
}

/// A single condition in a prevalence filter
/// Multiple conditions can be combined (all must be satisfied)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrevalenceCondition {
    /// Field to check
    pub field: PrevalenceField,
    /// Comparison operator
    pub operator: PrevalenceOperator,
    /// Threshold value
    pub threshold: PrevalenceThreshold,
}

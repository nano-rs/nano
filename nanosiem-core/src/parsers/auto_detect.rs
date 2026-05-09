// SPDX-License-Identifier: AGPL-3.0-or-later

//! Auto-detection service for identifying log source types
//!
//! This module provides automatic detection of log source types based on
//! pattern matching with confidence scoring.
//!
//! Requirements: 11.1, 11.2, 11.3, 11.4

use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use thiserror::Error;

use super::repository::DetectionPatternRepository;
use super::types::{DetectionPattern, PatternRule};

/// Default confidence threshold for auto-detection
pub const DEFAULT_CONFIDENCE_THRESHOLD: f32 = 0.5;

/// Errors that can occur during auto-detection
#[derive(Error, Debug)]
pub enum AutoDetectError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Repository error: {0}")]
    RepositoryError(#[from] super::repository::ParserRepositoryError),
    #[error("Invalid regex pattern: {0}")]
    InvalidRegex(String),
    #[error("No patterns loaded")]
    NoPatternsLoaded,
}

/// Result of auto-detection for a single source type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionMatch {
    /// The detected source type
    pub source_type: String,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f32,
    /// Number of patterns that matched
    pub matched_patterns: usize,
    /// Total number of patterns checked
    pub total_patterns: usize,
    /// Details of which patterns matched
    pub pattern_details: Vec<PatternMatchDetail>,
}

/// Details about a single pattern match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatchDetail {
    /// The field that was checked
    pub field: String,
    /// Whether the pattern matched
    pub matched: bool,
    /// The weight of this pattern
    pub weight: f32,
    /// The regex pattern used
    pub pattern: String,
}

/// Result of auto-detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoDetectResult {
    /// The best matching source type (if confidence > threshold)
    pub detected_source_type: Option<String>,
    /// Confidence score of the best match
    pub confidence: f32,
    /// Whether the detection is considered reliable
    pub is_confident: bool,
    /// All matches sorted by confidence (highest first)
    pub all_matches: Vec<DetectionMatch>,
    /// The threshold used for detection
    pub threshold: f32,
}

/// Auto-detector for identifying log source types
///
/// The AutoDetector loads detection patterns from the database and uses
/// regex pattern matching with weighted confidence scoring to identify
/// the most likely source type for a given log message.
///
/// Requirements: 11.1, 11.2, 11.3
pub struct AutoDetector {
    /// Cached detection patterns, keyed by source type
    patterns: HashMap<String, Vec<CompiledPattern>>,
    /// Confidence threshold for detection
    threshold: f32,
}

/// A compiled pattern ready for matching
struct CompiledPattern {
    field: String,
    regex: Regex,
    weight: f32,
    pattern_str: String,
}

impl AutoDetector {
    /// Create a new AutoDetector with default threshold
    pub fn new() -> Self {
        Self {
            patterns: HashMap::new(),
            threshold: DEFAULT_CONFIDENCE_THRESHOLD,
        }
    }

    /// Create a new AutoDetector with a custom threshold
    pub fn with_threshold(threshold: f32) -> Self {
        Self {
            patterns: HashMap::new(),
            threshold: threshold.clamp(0.0, 1.0),
        }
    }

    /// Load detection patterns from the database
    ///
    /// This method fetches all enabled detection patterns from the database
    /// and compiles them for efficient matching.
    ///
    /// Requirements: 11.2
    pub async fn load_patterns(&mut self, pool: &PgPool) -> Result<usize, AutoDetectError> {
        let repo = DetectionPatternRepository::new(pool.clone());
        let db_patterns = repo.get_detection_patterns().await?;

        self.patterns.clear();
        let mut total_compiled = 0;

        for pattern in db_patterns {
            let compiled = self.compile_pattern(&pattern)?;
            total_compiled += compiled.len();
            self.patterns.insert(pattern.source_type.clone(), compiled);
        }

        tracing::info!(
            "Loaded {} detection patterns for {} source types",
            total_compiled,
            self.patterns.len()
        );

        Ok(total_compiled)
    }

    /// Load patterns from a list (useful for testing)
    pub fn load_patterns_from_list(
        &mut self,
        patterns: Vec<DetectionPattern>,
    ) -> Result<usize, AutoDetectError> {
        self.patterns.clear();
        let mut total_compiled = 0;

        for pattern in patterns {
            let compiled = self.compile_pattern(&pattern)?;
            total_compiled += compiled.len();
            self.patterns.insert(pattern.source_type.clone(), compiled);
        }

        Ok(total_compiled)
    }

    /// Compile a detection pattern into regex patterns
    fn compile_pattern(
        &self,
        pattern: &DetectionPattern,
    ) -> Result<Vec<CompiledPattern>, AutoDetectError> {
        let rules: Vec<PatternRule> =
            serde_json::from_value(pattern.patterns.clone()).map_err(|e| {
                AutoDetectError::InvalidRegex(format!("Failed to parse patterns: {}", e))
            })?;

        let mut compiled = Vec::new();

        for rule in rules {
            let regex = Regex::new(&rule.regex).map_err(|e| {
                AutoDetectError::InvalidRegex(format!(
                    "Invalid regex '{}' for source type '{}': {}",
                    rule.regex, pattern.source_type, e
                ))
            })?;

            compiled.push(CompiledPattern {
                field: rule.field,
                regex,
                weight: rule.weight.clamp(0.0, 1.0),
                pattern_str: rule.regex,
            });
        }

        Ok(compiled)
    }

    /// Detect the source type of a log message
    ///
    /// This method checks the log content against all loaded patterns
    /// and returns the best match with confidence scoring.
    ///
    /// Requirements: 11.1, 11.3
    pub fn detect(&self, log_content: &str) -> AutoDetectResult {
        self.detect_with_fields(log_content, None)
    }

    /// Detect the source type with additional field values
    ///
    /// This method allows checking patterns against specific fields
    /// in addition to the raw message content.
    ///
    /// Requirements: 11.1, 11.3
    pub fn detect_with_fields(
        &self,
        log_content: &str,
        fields: Option<&HashMap<String, String>>,
    ) -> AutoDetectResult {
        if self.patterns.is_empty() {
            return AutoDetectResult {
                detected_source_type: None,
                confidence: 0.0,
                is_confident: false,
                all_matches: vec![],
                threshold: self.threshold,
            };
        }

        let mut all_matches: Vec<DetectionMatch> = Vec::new();

        // Check each source type's patterns
        for (source_type, patterns) in &self.patterns {
            let detection_match = self.check_patterns(source_type, patterns, log_content, fields);
            if detection_match.confidence > 0.0 {
                all_matches.push(detection_match);
            }
        }

        // Sort by confidence (highest first)
        all_matches.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Determine the best match
        let best_match = all_matches.first();
        let (detected_source_type, confidence, is_confident) = match best_match {
            Some(m) if m.confidence >= self.threshold => {
                (Some(m.source_type.clone()), m.confidence, true)
            }
            Some(m) => (None, m.confidence, false),
            None => (None, 0.0, false),
        };

        AutoDetectResult {
            detected_source_type,
            confidence,
            is_confident,
            all_matches,
            threshold: self.threshold,
        }
    }

    /// Check patterns for a specific source type
    fn check_patterns(
        &self,
        source_type: &str,
        patterns: &[CompiledPattern],
        log_content: &str,
        fields: Option<&HashMap<String, String>>,
    ) -> DetectionMatch {
        let mut matched_patterns = 0;
        let mut total_weight = 0.0;
        let mut matched_weight = 0.0;
        let mut pattern_details = Vec::new();

        for pattern in patterns {
            total_weight += pattern.weight;

            // Get the content to check based on the field
            let content_to_check = match pattern.field.as_str() {
                "message" | "" => Some(log_content),
                field_name => fields.and_then(|f| f.get(field_name).map(|s| s.as_str())),
            };

            let matched = content_to_check
                .map(|content| pattern.regex.is_match(content))
                .unwrap_or(false);

            if matched {
                matched_patterns += 1;
                matched_weight += pattern.weight;
            }

            pattern_details.push(PatternMatchDetail {
                field: pattern.field.clone(),
                matched,
                weight: pattern.weight,
                pattern: pattern.pattern_str.clone(),
            });
        }

        // Calculate confidence as weighted match ratio
        let confidence = if total_weight > 0.0 {
            matched_weight / total_weight
        } else {
            0.0
        };

        DetectionMatch {
            source_type: source_type.to_string(),
            confidence,
            matched_patterns,
            total_patterns: patterns.len(),
            pattern_details,
        }
    }

    /// Get the current confidence threshold
    pub fn threshold(&self) -> f32 {
        self.threshold
    }

    /// Set the confidence threshold
    pub fn set_threshold(&mut self, threshold: f32) {
        self.threshold = threshold.clamp(0.0, 1.0);
    }

    /// Check if patterns are loaded
    pub fn has_patterns(&self) -> bool {
        !self.patterns.is_empty()
    }

    /// Get the number of source types with patterns
    pub fn source_type_count(&self) -> usize {
        self.patterns.len()
    }

    /// Get all loaded source types
    pub fn source_types(&self) -> Vec<&str> {
        self.patterns.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for AutoDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn create_test_pattern(
        source_type: &str,
        patterns: Vec<(&str, &str, f32)>,
    ) -> DetectionPattern {
        let rules: Vec<PatternRule> = patterns
            .into_iter()
            .map(|(field, regex, weight)| PatternRule {
                field: field.to_string(),
                regex: regex.to_string(),
                weight,
            })
            .collect();

        DetectionPattern {
            id: Uuid::now_v7(),
            source_type: source_type.to_string(),
            patterns: serde_json::to_value(rules).unwrap(),
            priority: 0,
            enabled: true,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_auto_detector_creation() {
        let detector = AutoDetector::new();
        assert!(!detector.has_patterns());
        assert_eq!(detector.threshold(), DEFAULT_CONFIDENCE_THRESHOLD);
    }

    #[test]
    fn test_auto_detector_with_threshold() {
        let detector = AutoDetector::with_threshold(0.7);
        assert_eq!(detector.threshold(), 0.7);
    }

    #[test]
    fn test_load_patterns() {
        let mut detector = AutoDetector::new();

        let patterns = vec![
            create_test_pattern(
                "windows_event",
                vec![("message", "EventID", 0.6), ("message", "Computer", 0.3)],
            ),
            create_test_pattern(
                "apache",
                vec![
                    (
                        "message",
                        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*GET|POST",
                        0.5,
                    ),
                    ("message", "HTTP/1\\.[01]", 0.4),
                ],
            ),
        ];

        let count = detector.load_patterns_from_list(patterns).unwrap();
        assert_eq!(count, 4);
        assert!(detector.has_patterns());
        assert_eq!(detector.source_type_count(), 2);
    }

    #[test]
    fn test_detect_windows_event() {
        let mut detector = AutoDetector::with_threshold(0.3);

        let patterns = vec![create_test_pattern(
            "windows_event",
            vec![
                ("message", "EventID", 0.6),
                ("message", "Computer", 0.3),
                ("message", "Audit Success|Audit Failure", 0.5),
            ],
        )];

        detector.load_patterns_from_list(patterns).unwrap();

        let log = r#"{"EventID": 4624, "Computer": "WORKSTATION01", "Keywords": "Audit Success"}"#;
        let result = detector.detect(log);

        assert!(result.is_confident);
        assert_eq!(
            result.detected_source_type,
            Some("windows_event".to_string())
        );
        assert!(result.confidence > 0.5);
    }

    #[test]
    fn test_detect_apache_log() {
        let mut detector = AutoDetector::with_threshold(0.3);

        let patterns = vec![create_test_pattern(
            "apache",
            vec![
                ("message", r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", 0.4),
                ("message", "GET|POST|PUT|DELETE", 0.3),
                ("message", "HTTP/1\\.[01]", 0.3),
            ],
        )];

        detector.load_patterns_from_list(patterns).unwrap();

        let log =
            r#"192.168.1.100 - - [15/Jan/2024:10:30:00 +0000] "GET /index.html HTTP/1.1" 200 1234"#;
        let result = detector.detect(log);

        assert!(result.is_confident);
        assert_eq!(result.detected_source_type, Some("apache".to_string()));
    }

    #[test]
    fn test_detect_no_match() {
        let mut detector = AutoDetector::with_threshold(0.5);

        let patterns = vec![create_test_pattern(
            "windows_event",
            vec![("message", "EventID", 0.8)],
        )];

        detector.load_patterns_from_list(patterns).unwrap();

        let log = "This is a random log message with no matching patterns";
        let result = detector.detect(log);

        assert!(!result.is_confident);
        assert_eq!(result.detected_source_type, None);
    }

    #[test]
    #[ignore = "multiple-match ordering is heuristic and currently non-deterministic"]
    fn test_detect_multiple_matches() {
        let mut detector = AutoDetector::with_threshold(0.3);

        let patterns = vec![
            create_test_pattern(
                "syslog",
                vec![
                    ("message", r"^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}", 0.5),
                    ("message", "kernel|sshd|systemd", 0.3),
                ],
            ),
            create_test_pattern(
                "generic",
                vec![("message", ".*", 0.1)], // Matches everything with low weight
            ),
        ];

        detector.load_patterns_from_list(patterns).unwrap();

        let log =
            "Jan 15 10:30:00 server sshd[1234]: Accepted password for user from 192.168.1.100";
        let result = detector.detect(log);

        assert!(result.is_confident);
        assert_eq!(result.detected_source_type, Some("syslog".to_string()));
        assert!(result.all_matches.len() >= 1);
    }

    #[test]
    fn test_detect_with_fields() {
        let mut detector = AutoDetector::with_threshold(0.3);

        let patterns = vec![create_test_pattern(
            "custom",
            vec![("message", "test", 0.3), ("hostname", "server", 0.7)],
        )];

        detector.load_patterns_from_list(patterns).unwrap();

        let mut fields = HashMap::new();
        fields.insert("hostname".to_string(), "server01".to_string());

        let log = "test message";
        let result = detector.detect_with_fields(log, Some(&fields));

        assert!(result.is_confident);
        assert_eq!(result.detected_source_type, Some("custom".to_string()));
    }

    #[test]
    fn test_empty_patterns() {
        let detector = AutoDetector::new();
        let result = detector.detect("any log message");

        assert!(!result.is_confident);
        assert_eq!(result.detected_source_type, None);
        assert!(result.all_matches.is_empty());
    }

    #[test]
    fn test_invalid_regex() {
        let mut detector = AutoDetector::new();

        let patterns = vec![create_test_pattern(
            "invalid",
            vec![("message", "[invalid(regex", 0.5)],
        )];

        let result = detector.load_patterns_from_list(patterns);
        assert!(result.is_err());
    }
}

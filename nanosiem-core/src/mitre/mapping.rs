// SPDX-License-Identifier: AGPL-3.0-or-later

//! Canonical MITRE ATT&CK rule-mapping contracts.

use std::collections::BTreeSet;

use thiserror::Error;

pub(crate) const MITRE_MAPPING_CONSTRAINT: &str = "detection_rules_mitre_mapping_check";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalMitreMappings {
    pub tactics: Vec<String>,
    pub techniques: Vec<String>,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub(crate) enum MitreMappingError {
    #[error("Invalid MITRE tactic ID '{0}'; expected TA followed by four digits")]
    InvalidTacticId(String),
    #[error(
        "Invalid MITRE technique ID '{0}'; expected T followed by four digits and an optional three-digit sub-technique"
    )]
    InvalidTechniqueId(String),
    #[error("MITRE tactics and techniques must either both be empty or both be provided")]
    IncompleteMapping,
}

pub(crate) fn canonicalize_mitre_mappings(
    tactics: &[String],
    techniques: &[String],
) -> Result<CanonicalMitreMappings, MitreMappingError> {
    let tactics = canonicalize_tactic_ids(tactics)?;
    let techniques = canonicalize_technique_ids(techniques)?;
    if tactics.is_empty() != techniques.is_empty() {
        return Err(MitreMappingError::IncompleteMapping);
    }
    Ok(CanonicalMitreMappings {
        tactics,
        techniques,
    })
}

pub(crate) fn canonicalize_tactic_ids(values: &[String]) -> Result<Vec<String>, MitreMappingError> {
    canonicalize_ids(values, is_tactic_id, MitreMappingError::InvalidTacticId)
}

pub(crate) fn canonicalize_technique_ids(
    values: &[String],
) -> Result<Vec<String>, MitreMappingError> {
    canonicalize_ids(
        values,
        is_technique_id,
        MitreMappingError::InvalidTechniqueId,
    )
}

fn canonicalize_ids(
    values: &[String],
    valid: fn(&str) -> bool,
    error: fn(String) -> MitreMappingError,
) -> Result<Vec<String>, MitreMappingError> {
    let mut canonical = BTreeSet::new();
    for value in values {
        let value = value.trim().to_ascii_uppercase();
        if !valid(&value) {
            return Err(error(value));
        }
        canonical.insert(value);
    }
    Ok(canonical.into_iter().collect())
}

fn is_tactic_id(value: &str) -> bool {
    value.len() == 6
        && value.starts_with("TA")
        && value[2..].bytes().all(|byte| byte.is_ascii_digit())
}

fn is_technique_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (bytes.len() == 5 && bytes[0] == b'T' && bytes[1..].iter().all(u8::is_ascii_digit))
        || (bytes.len() == 9
            && bytes[0] == b'T'
            && bytes[1..5].iter().all(u8::is_ascii_digit)
            && bytes[5] == b'.'
            && bytes[6..].iter().all(u8::is_ascii_digit))
}

pub(crate) fn database_mapping_violation(error: &sqlx::Error) -> Option<String> {
    let sqlx::Error::Database(database) = error else {
        return None;
    };
    (database.constraint() == Some(MITRE_MAPPING_CONSTRAINT))
        .then(|| database.message().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn assert_database_rejects(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tactics: &[&str],
        techniques: &[&str],
        message: &str,
    ) {
        sqlx::query("SAVEPOINT mitre_mapping_case")
            .execute(&mut **transaction)
            .await
            .unwrap();
        let error = sqlx::query(
            "INSERT INTO detection_rules \
             (name, query, severity, mitre_tactics, mitre_techniques) \
             VALUES ($1, '*', 'medium', $2, $3)",
        )
        .bind(format!("NAN-1774 invalid {}", uuid::Uuid::now_v7()))
        .bind(tactics)
        .bind(techniques)
        .execute(&mut **transaction)
        .await
        .expect_err("invalid mapping must be rejected");
        assert_eq!(database_mapping_violation(&error).as_deref(), Some(message));
        sqlx::query("ROLLBACK TO SAVEPOINT mitre_mapping_case")
            .execute(&mut **transaction)
            .await
            .unwrap();
        sqlx::query("RELEASE SAVEPOINT mitre_mapping_case")
            .execute(&mut **transaction)
            .await
            .unwrap();
    }

    #[test]
    fn mappings_are_trimmed_uppercased_sorted_and_deduplicated() {
        let mappings = canonicalize_mitre_mappings(
            &[" ta0002 ".into(), "TA0001".into(), "ta0002".into()],
            &[" t1059.001 ".into(), "T1078".into(), "t1059.001".into()],
        )
        .unwrap();

        assert_eq!(mappings.tactics, ["TA0001", "TA0002"]);
        assert_eq!(mappings.techniques, ["T1059.001", "T1078"]);
    }

    #[test]
    fn invalid_and_incomplete_shapes_are_rejected() {
        assert!(matches!(
            canonicalize_mitre_mappings(&["TA01".into()], &["T1059".into()]),
            Err(MitreMappingError::InvalidTacticId(_))
        ));
        assert!(matches!(
            canonicalize_mitre_mappings(&["TA0002".into()], &["T1059.1".into()]),
            Err(MitreMappingError::InvalidTechniqueId(_))
        ));
        assert_eq!(
            canonicalize_mitre_mappings(&["TA0002".into()], &[]),
            Err(MitreMappingError::IncompleteMapping)
        );
        assert!(canonicalize_mitre_mappings(&[], &[]).is_ok());
    }

    #[tokio::test]
    #[ignore = "requires migrated PostgreSQL"]
    async fn database_contract_covers_unknown_deprecated_mismatch_and_subtechniques() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://nanosiem:nanosiem@localhost:5432/nanosiem".into());
        let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        let mut transaction = pool.begin().await.unwrap();

        for (id, name) in [("TA9998", "Test A"), ("TA9999", "Test B")] {
            sqlx::query(
                "INSERT INTO mitre_tactics (id, name, short_name) VALUES ($1, $2, $1) \
                 ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name",
            )
            .bind(id)
            .bind(name)
            .execute(&mut *transaction)
            .await
            .unwrap();
        }
        for (id, is_subtechnique, parent_id, deprecated) in [
            ("T9998", false, None, false),
            ("T9999", false, None, false),
            ("T9999.001", true, Some("T9999"), false),
            ("T9997", false, None, true),
        ] {
            sqlx::query(
                "INSERT INTO mitre_techniques \
                 (id, name, is_subtechnique, parent_id, deprecated) \
                 VALUES ($1, $1, $2, $3, $4) \
                 ON CONFLICT (id) DO UPDATE SET \
                    is_subtechnique=EXCLUDED.is_subtechnique, \
                    parent_id=EXCLUDED.parent_id, deprecated=EXCLUDED.deprecated",
            )
            .bind(id)
            .bind(is_subtechnique)
            .bind(parent_id)
            .bind(deprecated)
            .execute(&mut *transaction)
            .await
            .unwrap();
        }
        for (technique, tactic) in [
            ("T9998", "TA9998"),
            ("T9999", "TA9999"),
            ("T9999.001", "TA9999"),
            ("T9997", "TA9998"),
        ] {
            sqlx::query(
                "INSERT INTO mitre_technique_tactics (technique_id, tactic_id) \
                 VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(technique)
            .bind(tactic)
            .execute(&mut *transaction)
            .await
            .unwrap();
        }

        let canonical: (Vec<String>, Vec<String>) = sqlx::query_as(
            "INSERT INTO detection_rules \
             (name, query, severity, mitre_tactics, mitre_techniques) \
             VALUES ($1, '*', 'medium', $2, $3) \
             RETURNING mitre_tactics, mitre_techniques",
        )
        .bind(format!("NAN-1774 canonical {}", uuid::Uuid::now_v7()))
        .bind(&[" ta9999 ", "TA9999"])
        .bind(&["t9999.001", "T9999.001"])
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
        assert_eq!(canonical.0, ["TA9999"]);
        assert_eq!(canonical.1, ["T9999.001"]);

        assert_database_rejects(
            &mut transaction,
            &["TA9996"],
            &["T9998"],
            "Unknown MITRE tactic 'TA9996'; synchronize the ATT&CK catalog before saving this mapping",
        )
        .await;
        assert_database_rejects(
            &mut transaction,
            &["TA9998"],
            &["T9996"],
            "Unknown or deprecated MITRE technique 'T9996'",
        )
        .await;
        assert_database_rejects(
            &mut transaction,
            &["TA9998"],
            &["T9997"],
            "Unknown or deprecated MITRE technique 'T9997'",
        )
        .await;
        assert_database_rejects(
            &mut transaction,
            &["TA9998"],
            &["T9999"],
            "MITRE technique 'T9999' does not belong to any listed tactic",
        )
        .await;
        assert_database_rejects(
            &mut transaction,
            &["TA9998", "TA9999"],
            &["T9998"],
            "MITRE tactic 'TA9999' is not represented by any listed technique",
        )
        .await;
        assert_database_rejects(
            &mut transaction,
            &["TA9998"],
            &[],
            "MITRE tactics and techniques must either both be empty or both be provided",
        )
        .await;

        transaction.rollback().await.unwrap();
    }
}

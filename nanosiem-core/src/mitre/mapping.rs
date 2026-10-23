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

/// NAN-4372: the verdict a rule write would get on its MITRE mapping, for
/// `POST /api/rules/validate` (which used to check none of it, so a mismatched
/// tactic/technique pair surfaced only at create).
///
/// Runs exactly the checks a write runs, in the same order: the Rust shape
/// canonicalization the repository applies before INSERT/UPDATE
/// ([`canonicalize_mitre_mappings`]), then the catalog checks the
/// `detection_rules_mitre_mapping_check` trigger applies, through the same SQL
/// functions it calls (`resolve_mitre_technique_alias` /
/// `remap_mitre_mapping` for renumbered techniques, then
/// `mitre_mapping_rejection_reason`), including its air-gapped skip when the
/// catalog is empty. Read-only. `Ok(None)` means a write would accept it.
pub async fn validate_mitre_mapping_for_write<'e, E>(
    executor: E,
    tactics: &[String],
    techniques: &[String],
) -> Result<Option<String>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let mappings = match canonicalize_mitre_mappings(tactics, techniques) {
        Ok(mappings) => mappings,
        Err(error) => return Ok(Some(error.to_string())),
    };
    if mappings.tactics.is_empty() && mappings.techniques.is_empty() {
        return Ok(None);
    }
    let reason: Option<String> = sqlx::query_scalar(
        r#"
        WITH input AS (SELECT $1::text[] AS tactics, $2::text[] AS techniques),
        catalog AS (
            SELECT EXISTS (SELECT 1 FROM public.mitre_tactics)
               AND EXISTS (SELECT 1 FROM public.mitre_techniques) AS present
        ),
        remap AS (
            SELECT EXISTS (
                SELECT 1 FROM input, unnest(input.techniques) AS requested(id)
                WHERE NOT EXISTS (SELECT 1 FROM public.mitre_techniques AS t WHERE t.id = requested.id)
                  AND public.resolve_mitre_technique_alias(requested.id) IS NOT NULL
            ) AS needed
        ),
        mapped AS (
            SELECT
                CASE WHEN remap.needed
                    THEN (public.remap_mitre_mapping(input.tactics, input.techniques)).out_tactics
                    ELSE input.tactics END AS tactics,
                CASE WHEN remap.needed
                    THEN (public.remap_mitre_mapping(input.tactics, input.techniques)).out_techniques
                    ELSE input.techniques END AS techniques
            FROM input, remap
        )
        SELECT CASE WHEN catalog.present
            THEN public.mitre_mapping_rejection_reason(mapped.tactics, mapped.techniques)
        END
        FROM mapped, catalog
        "#,
    )
    .bind(&mappings.tactics)
    .bind(&mappings.techniques)
    .fetch_one(executor)
    .await?;
    Ok(reason.map(|reason| format!("Invalid MITRE ATT&CK mapping: {reason}")))
}

/// NAN-4372: whether a validate for an UPDATE leaves the rule's stored MITRE
/// mapping unchanged, in which case the write trigger skips its catalog checks
/// (`TG_OP = 'UPDATE' AND NEW.* IS NOT DISTINCT FROM OLD.*`) and validate must
/// not report the mapping invalid either.
///
/// `stored` is the edited rule's `(mitre_tactics, mitre_techniques)` row, or
/// `None` for a create / unknown rule. A list absent from the request keeps
/// its stored value, as an update that omits it does. The request side is
/// canonicalized the way the repository canonicalizes it before the UPDATE;
/// a request that fails canonicalization is never "unchanged".
pub fn mitre_mapping_unchanged(
    stored: Option<&(Option<Vec<String>>, Option<Vec<String>>)>,
    tactics: Option<&[String]>,
    techniques: Option<&[String]>,
) -> bool {
    let Some((stored_tactics, stored_techniques)) = stored else {
        return false;
    };
    let stored_tactics = stored_tactics.as_deref().unwrap_or_default();
    let stored_techniques = stored_techniques.as_deref().unwrap_or_default();
    let Ok(requested) = canonicalize_mitre_mappings(
        tactics.unwrap_or(stored_tactics),
        techniques.unwrap_or(stored_techniques),
    ) else {
        return false;
    };
    requested.tactics == stored_tactics && requested.techniques == stored_techniques
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
    #[test]
    fn unchanged_mapping_mirrors_the_trigger_update_skip() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let stored = (Some(s(&["TA0002"])), Some(s(&["T1059.001"])));
        // Same mapping (modulo case/whitespace the repository canonicalizes).
        assert!(mitre_mapping_unchanged(Some(&stored), Some(&s(&[" ta0002"])), Some(&s(&["T1059.001"]))));
        // An omitted list keeps its stored value.
        assert!(mitre_mapping_unchanged(Some(&stored), None, Some(&s(&["T1059.001"]))));
        // Changed, create (no stored row), or malformed: validate checks it.
        assert!(!mitre_mapping_unchanged(Some(&stored), Some(&s(&["TA0003"])), Some(&s(&["T1059.001"]))));
        assert!(!mitre_mapping_unchanged(None, Some(&s(&["TA0002"])), Some(&s(&["T1059.001"]))));
        assert!(!mitre_mapping_unchanged(Some(&stored), Some(&s(&["TA02"])), Some(&s(&["T1059.001"]))));
    }

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

    /// NAN-4372: validate's verdict equals the write path's on the same
    /// mappings — accepted when an INSERT would be, refused (with the same
    /// reason) when the trigger would refuse it. Runs against the real
    /// migrated catalog.
    #[tokio::test]
    #[ignore = "requires migrated PostgreSQL"]
    async fn validate_verdict_matches_the_write_trigger() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://nanosiem:nanosiem@localhost:5432/nanosiem".into());
        let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        let s = |values: &[&str]| values.iter().map(|v| v.to_string()).collect::<Vec<_>>();
        // (tactics, techniques, accepted)
        let cases: &[(&[&str], &[&str], bool)] = &[
            (&["TA0002"], &["T1059.001"], true),
            (&["ta0002"], &[" t1059.001 "], true),
            (&[], &[], true),
            // Credential Access does not contain Command and Scripting Interpreter.
            (&["TA0006"], &["T1059.001"], false),
            (&["TA0002"], &[], false),
            (&["BANANA"], &["T1059"], false),
            (&["TA9990"], &["T1059"], false),
        ];
        for (tactics, techniques, accepted) in cases {
            let verdict = validate_mitre_mapping_for_write(&pool, &s(tactics), &s(techniques))
                .await
                .unwrap();
            assert_eq!(verdict.is_none(), *accepted, "{tactics:?}/{techniques:?}: {verdict:?}");

            let mut transaction = pool.begin().await.unwrap();
            let written = sqlx::query(
                "INSERT INTO detection_rules (name, query, severity, mitre_tactics, mitre_techniques) \
                 VALUES ($1, '*', 'medium', $2, $3)",
            )
            .bind(format!("NAN-4372 validate parity {}", uuid::Uuid::now_v7()))
            .bind(s(tactics).iter().map(|v| v.trim().to_ascii_uppercase()).collect::<Vec<_>>())
            .bind(s(techniques).iter().map(|v| v.trim().to_ascii_uppercase()).collect::<Vec<_>>())
            .execute(&mut *transaction)
            .await;
            transaction.rollback().await.unwrap();
            if *accepted {
                written.unwrap();
            } else if let Err(error) = written {
                assert!(database_mapping_violation(&error).is_some(), "{error}");
            } else {
                // Shape errors are refused by the repository before the INSERT.
                assert!(canonicalize_mitre_mappings(&s(tactics), &s(techniques)).is_err());
            }
        }
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

    /// NAN-1918 regression guard.
    ///
    /// Migration 230 ran the ID *shape* checks before the empty-catalog guard on
    /// purpose: an air-gapped install never syncs a catalog, but `'BANANA'` is
    /// still not a tactic ID. While adding alias remapping I folded those checks
    /// into the catalog-aware validation, which sits *after* that guard — so
    /// every malformed ID silently became valid on air-gapped deployments, and
    /// the whole suite stayed green. Pin the ordering.
    #[tokio::test]
    #[ignore = "requires migrated PostgreSQL"]
    async fn malformed_ids_are_rejected_even_without_a_catalog() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://nanosiem:nanosiem@localhost:5432/nanosiem".into());
        let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        let mut transaction = pool.begin().await.unwrap();

        // Simulate the air-gapped shape: catalog tables empty, rolled back after.
        for table in [
            "mitre_technique_tactics",
            "mitre_techniques",
            "mitre_tactics",
        ] {
            sqlx::query(&format!("DELETE FROM {table}"))
                .execute(&mut *transaction)
                .await
                .unwrap();
        }

        assert_database_rejects(
            &mut transaction,
            &["BANANA"],
            &["T1059"],
            "Invalid MITRE tactic ID 'BANANA'; expected TA followed by four digits",
        )
        .await;
        assert_database_rejects(
            &mut transaction,
            &["TA0002"],
            &["not-a-technique"],
            "Invalid MITRE technique ID 'NOT-A-TECHNIQUE'; expected T followed by four digits and an optional three-digit sub-technique",
        )
        .await;

        // The degrade itself must survive: a well-formed mapping still writes,
        // otherwise an air-gapped install could not create rules at all.
        sqlx::query(
            "INSERT INTO detection_rules \
             (name, query, severity, mitre_tactics, mitre_techniques) \
             VALUES ($1, '*', 'medium', ARRAY['TA0002'], ARRAY['T1059'])",
        )
        .bind(format!("NAN-1918 airgap ok {}", uuid::Uuid::now_v7()))
        .execute(&mut *transaction)
        .await
        .expect("well-formed mapping must still write without a catalog");

        transaction.rollback().await.unwrap();
    }
}

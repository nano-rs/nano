// SPDX-License-Identifier: AGPL-3.0-or-later

//! CRUD operations for log sources

use sqlx;
use uuid::Uuid;

use super::LogSourceService;
use super::LogSourceServiceError;
use crate::log_sources::types::{ListParams, LogSource, NewLogSource, SourceType, UpdateLogSource};

/// NAN-2158: reject a `match_field` that is not a bare SQL identifier.
///
/// `match_field` names the COLUMN the source-health query matches on, and it is
/// interpolated into generated ClickHouse SQL (`lower({field}) IN (…)`). The
/// match VALUES are escaped; the identifier is not — a stored
/// `source_type) = 'audit' --` closes the `lower(` early and comments out the
/// rest of the line, including the source-scope predicate appended after it.
///
/// The read sink validates too (`log_sources::repository::health`), which is
/// what neutralizes rows already persisted with a hostile value. This is the
/// other half: stop accepting them, and tell the caller why instead of silently
/// downgrading the field to `source_type` at query time.
///
/// Applied in the SERVICE, not the HTTP handler, so it also covers the
/// non-HTTP writers — content-repository parser import
/// (`parser_repository::service`) and the AI log-source wizard — which build a
/// `NewLogSource` directly.
///
/// `None` / empty is allowed: both mean "no explicit match column", and the
/// sink falls back to `source_type`.
pub(super) fn validate_match_field(match_field: Option<&str>) -> Result<(), LogSourceServiceError> {
    let Some(field) = match_field else {
        return Ok(());
    };
    if field.is_empty() {
        return Ok(());
    }
    if !crate::sql_hygiene::is_safe_sql_identifier(field) {
        return Err(LogSourceServiceError::InvalidMatchField(format!(
            "'{field}' is not a column name — match_field must contain only \
             letters, digits, '_' and '.'"
        )));
    }
    Ok(())
}

impl LogSourceService {
    /// List all log sources with optional filtering.
    pub async fn list(
        &self,
        params: Option<ListParams>,
    ) -> Result<Vec<LogSource>, LogSourceServiceError> {
        let params = params.unwrap_or_default();
        Ok(self.repository().list(&params).await?)
    }

    /// List enabled log sources.
    pub async fn list_enabled(&self) -> Result<Vec<LogSource>, LogSourceServiceError> {
        Ok(self.repository().list_enabled().await?)
    }

    /// List deployed log sources.
    pub async fn list_deployed(&self) -> Result<Vec<LogSource>, LogSourceServiceError> {
        Ok(self.repository().list_deployed().await?)
    }

    /// Get a log source by ID.
    pub async fn get(&self, id: Uuid) -> Result<LogSource, LogSourceServiceError> {
        Ok(self.repository().find_by_id(id).await?)
    }

    /// Get a log source by name.
    pub async fn get_by_name(&self, name: &str) -> Result<LogSource, LogSourceServiceError> {
        Ok(self.repository().find_by_name(name).await?)
    }

    /// Enforce the data-source tier cap. See
    /// [`crate::log_sources::enforce_data_source_limit`] — this is the
    /// convenience form for callers that already hold a service and have no
    /// transaction to serialize the check against.
    pub async fn enforce_data_source_limit(&self) -> Result<(), crate::TierError> {
        crate::log_sources::enforce_data_source_limit(&self.pool).await
    }

    /// Create a new log source
    /// NAN-2311: reject a name whose GENERATED Vector identifier is already
    /// taken by another log source.
    ///
    /// `safe_name` maps every non-alphanumeric character to `_`, so "My Source",
    /// "my-source" and "my_source" all become `my_source` — one filename, one
    /// set of transform ids, one router route key. The table's `UNIQUE(name)`
    /// happily accepts all three.
    ///
    /// NAN-2305 added this guard to `ParserService`, but `POST /api/log-sources`
    /// goes through THIS service, so the guard never ran on the path the API
    /// and UI actually use. Migration 283's unique index still stopped the
    /// write, which meant the operator got `500 A database error occurred`
    /// instead of being told which source holds the name. Verified against a
    /// live tenant before this fix.
    ///
    /// Racy on its own (list-then-write); the index remains the backstop for
    /// two concurrent creates. This runs first so the ordinary case gets a
    /// message naming the conflict.
    async fn ensure_generated_identity_free(
        &self,
        name: &str,
        exclude: Option<Uuid>,
    ) -> Result<(), LogSourceServiceError> {
        let existing = self.repository().list_identities().await?;
        match crate::vector_naming::generated_identity_conflict(
            "log source",
            name,
            &existing,
            exclude,
        ) {
            Some(detail) => Err(LogSourceServiceError::NameCollision(detail)),
            None => Ok(()),
        }
    }

    pub async fn create(&self, new: NewLogSource) -> Result<LogSource, LogSourceServiceError> {
        // Validate source type
        if SourceType::from_str(&new.source_type).is_none() {
            return Err(LogSourceServiceError::InvalidSourceType(
                new.source_type.clone(),
            ));
        }

        // The name lands in a generated TOML section/comment header — reject
        // control chars at the boundary, not just via generator escaping (NAN-1371).
        crate::config_safety::validate_config_name(&new.name)
            .map_err(LogSourceServiceError::InvalidSourceConfig)?;

        // NAN-2158: `match_field` is a SQL column identifier, not a value.
        validate_match_field(new.match_field.as_deref())?;

        // NAN-2311: UNIQUE(name) accepts `my-source` beside `My Source`; the
        // generated Vector namespace does not.
        self.ensure_generated_identity_free(&new.name, None).await?;

        // Create in database
        let log_source = self.repository().create(&new).await?;

        tracing::info!(
            "Created log source '{}' ({}) with source type '{}'",
            log_source.name,
            log_source.id,
            log_source.source_type
        );

        // Validate VRL and set validation status
        let validation = self.validate_vrl(&log_source.parser_vrl).await;
        let error_msg = if validation.valid {
            None
        } else {
            Some(validation.errors.join("; "))
        };

        self.repository()
            .set_validation_status(log_source.id, validation.valid, error_msg.as_deref())
            .await?;

        // Return the updated log source with correct validation status.
        Ok(self.repository().find_by_id(log_source.id).await?)
    }

    /// Update a log source
    pub async fn update(
        &self,
        id: Uuid,
        update: UpdateLogSource,
    ) -> Result<LogSource, LogSourceServiceError> {
        // Validate source type if being updated
        if let Some(ref source_type) = update.source_type {
            if SourceType::from_str(source_type).is_none() {
                return Err(LogSourceServiceError::InvalidSourceType(
                    source_type.clone(),
                ));
            }
        }

        // NAN-2311: a RENAME can collide just as a create can. `exclude` is the
        // row being renamed, so keeping its own name is not a self-conflict.
        if let Some(ref name) = update.name {
            self.ensure_generated_identity_free(name, Some(id)).await?;
        }

        // NAN-1197: an enrichment source's `normalize_vrl` is embedded verbatim
        // into the generated Vector lane TOML. The deploy-time chokepoint
        // (`guard_enrichment_lane`) already rejects a `'''`/TOML-header breakout,
        // but validate here too so the API caller gets an immediate, clear error
        // at save time instead of a later opaque deploy failure (the log-source
        // update path historically validated `parser_vrl` only).
        if let Some(ref nvrl) = update.normalize_vrl {
            if !nvrl.trim().is_empty() {
                if let Err(e) = crate::parsers::VrlValidator::new().check_normalize_vrl_safety(nvrl)
                {
                    return Err(LogSourceServiceError::InvalidVrl(format!(
                        "normalize_vrl: {e}"
                    )));
                }
            }
        }

        // Config-injection guard (NAN-1371): same char-safety checks as create,
        // applied to the fields being updated.
        if let Some(ref name) = update.name {
            crate::config_safety::validate_config_name(name)
                .map_err(LogSourceServiceError::InvalidSourceConfig)?;
        }

        // NAN-2158: `match_field` is a SQL column identifier, not a value.
        // `None` means "no change" (the repository UPDATE uses COALESCE) and is
        // not validated; anything actually being WRITTEN is. Note that the UI
        // PUTs the whole object, so re-saving a row that already holds a legacy
        // hostile value is refused with a named error — deliberately, since the
        // alternative is the read sink silently downgrading it to `source_type`
        // forever with only a log line to show for it.
        validate_match_field(update.match_field.as_deref())?;
        let log_source = self.repository().update(id, &update).await?;

        // If VRL was updated, validate and set the correct status
        if update.parser_vrl.is_some() {
            let validation = self.validate_vrl(&log_source.parser_vrl).await;
            let error_msg = if validation.valid {
                None
            } else {
                Some(validation.errors.join("; "))
            };

            self.repository()
                .set_validation_status(id, validation.valid, error_msg.as_deref())
                .await?;
        }

        tracing::info!(
            "Updated log source '{}' ({})",
            log_source.name,
            log_source.id
        );

        // Return the updated log source with correct validation status.
        Ok(self.repository().find_by_id(id).await?)
    }

    /// Delete a log source
    ///
    /// This removes the log source from the database and cleans up the Vector config files.
    /// The combiner and router configs are also updated to remove references to the deleted log source.
    pub async fn delete(&self, id: Uuid) -> Result<(), LogSourceServiceError> {
        let log_source = self.repository().find_by_id(id).await?;
        let log_source_name = log_source.name.clone();

        // NAN-2305: the active Vector tree is republished BEFORE the row goes,
        // in one locked pass, and the parser TOML is no longer unlinked on its
        // own.
        //
        // The old order was: delete the row, unlink the parser TOML while
        // holding no lock, then call the self-locking redeploy. Between the
        // unlink and the redeploy — a window that includes waiting for whatever
        // deploy already held the mutex — `_combiner.toml` named a transform
        // whose file no longer existed. Vector treats an input naming a missing
        // component as fatal to the WHOLE config, so any reload in that window
        // (a concurrent deploy's, or `--watch-config` reacting to the unlink
        // itself) was rejected and Vector kept running the pre-delete topology.
        // The redeploy's own failure was then only warned about and the
        // deletion still reported success.
        //
        // Regenerating from the surviving sources does the removal as part of a
        // coherent write: `deploy_parsers` prunes the orphaned parser file and
        // rewrites the combiner and router in the same pass, so no intermediate
        // state is ever visible on disk.
        {
            let _deploy_guard = self.vector_config.lock_deploys().await;

        // Regenerate the whole tree from the surviving sources, ALWAYS.
        //
        // NAN-2310: this used to be gated on `was_deployed`, with the other arm
        // just unlinking the parser file on the reasoning that a
        // never-deployed source has no live topology referencing it. That
        // reasoning does not survive contact with the `deployed` flag, which
        // `update` clears whenever a deployment-affecting field changes
        // (`repository/crud.rs`: `deployed = CASE WHEN $18 THEN false ...`).
        //
        // So the ordinary sequence create -> publish -> edit the VRL -> delete
        // left `deployed = false` while `_combiner.toml` and `_router.toml`
        // still named the source's `<name>_output`. Unlinking only the parser
        // file produced exactly the NAN-2296 failure: a dangling input that
        // makes the ENTIRE Vector config unloadable, so every subsequent reload
        // is rejected and the collector is frozen on its last good config.
        // Reproduced on a live tenant: `vector validate` failed with
        // `Input "…_output" for transform "db_parsers_combined" doesn't match
        // any components`, and Vector logged `reload aborted`.
        //
        // Regeneration is the coherent operation in both cases: for a source
        // that was live it rewrites the combiner and router without it, and for
        // one that never deployed it is a no-op that still prunes any stale
        // file. There is no case where unlinking alone is more correct, so the
        // branch is gone rather than repaired.
        {
            // NAN-2304 gives us the canonical effective-deployed query (it also
            // resolves dispatch route names internally). NAN-2305's `filter` is
            // still required and must not be dropped in a merge: the row is
            // deleted AFTER this regeneration, inside the deploy guard, so it is
            // still present here — regenerating without the filter would write a
            // config that still routes the source being deleted.
            let parsers: Vec<_> = self
                .effective_deployed_parsers()
                .await?
                .into_iter()
                .filter(|parser| parser.id != id)
                .collect();

                // Fail closed. The row is still present, so the DB and the
                // config still agree and the operator can retry — far better
                // than a "deleted" source that the collector keeps routing to.
                if let Err(e) = self.vector_config.deploy_parsers(&parsers).await {
                    tracing::error!(
                        "Refusing to delete log source '{}': could not regenerate the Vector \
                         config without it: {}",
                        log_source_name,
                        e
                    );
                    return Err(LogSourceServiceError::VectorConfigError(e));
                }

                // Deliberately NOT fatal, unlike the write above: the on-disk
                // tree is already correct and coherent at this point, so the
                // worst case is that Vector keeps a now-unused route until the
                // next reload. Blocking deletion behind a collector that is
                // down or unreachable would be the worse failure.
                if let Err(e) = self.vector_config.reload_vector().await {
                    tracing::error!(
                        "Vector config for deleted log source '{}' was written but Vector did not \
                         confirm the reload — it may still be routing the deleted source until it \
                         next reloads: {}",
                        log_source_name,
                        e
                    );
                }
            }

            // Inside the guard, with the config already republished. Dropping
            // the lock first would leave a window in which a concurrent deploy
            // reads the still-present row, regenerates from it, and puts the
            // source being deleted straight back into the config — the row then
            // disappears underneath it and the collector is left routing a
            // source nobody can manage.
            //
            // Config-before-row is also the safer order for the failure case:
            // if this DELETE fails, the source is absent from the config but
            // still in the database, so the next deploy restores it and the
            // delete simply did not happen. The reverse leaves a deleted source
            // live in the collector, which is what the old ordering did.
            self.repository().delete(id).await?;
        }

        // Clean up orphaned routing rules that targeted this log source's source_type.
        // We only delete from the DB — no source config deploy or router update needed.
        // The next explicit source config deploy will regenerate configs without these rules.
        let source_type = &log_source.source_type;
        match sqlx::query("DELETE FROM routing_rules WHERE target_source_type = $1")
            .bind(source_type)
            .execute(&self.pool)
            .await
        {
            Ok(result) if result.rows_affected() > 0 => {
                tracing::info!(
                    "Removed {} orphaned routing rule(s) targeting source_type '{}'",
                    result.rows_affected(),
                    source_type
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to clean up routing rules for source_type '{}': {}",
                    source_type,
                    e
                );
            }
            _ => {}
        }

        tracing::info!("Deleted log source '{}' ({})", log_source_name, id);

        Ok(())
    }
}

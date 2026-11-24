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

/// NAN-5839: a log source's timezone, validated and in its stored spelling
/// (see [`crate::timezone::normalize_source_timezone`]). Every writer that goes
/// through the service (API create/update, wizard drafts, imports) runs it.
pub(super) fn normalize_timezone(timezone: &str) -> Result<String, LogSourceServiceError> {
    crate::timezone::normalize_source_timezone(timezone).map_err(LogSourceServiceError::InvalidTimezone)
}

/// NAN-5012: a non-blank sampling exclude condition must pass
/// [`crate::parsers::vrl_safety::check_condition`]. Blank means "no condition".
pub(super) fn check_sampling_condition(
    condition: Option<&str>,
) -> Result<(), LogSourceServiceError> {
    match condition.map(str::trim).filter(|c| !c.is_empty()) {
        Some(condition) => {
            crate::parsers::vrl_safety::check_condition("sampling_exclude_condition", condition)
                .map_err(LogSourceServiceError::InvalidVrl)
        }
        None => Ok(()),
    }
}

/// NAN-5057: an enabled, non-blank extension must pass the same allowlist
/// check as the parser it runs after.
pub(super) fn check_extension(enabled: bool, extension_vrl: Option<&str>) -> Result<(), String> {
    match extension_vrl.filter(|v| enabled && !v.trim().is_empty()) {
        Some(vrl) => crate::parsers::vrl_safety::check_program("extension_vrl", vrl),
        None => Ok(()),
    }
}

/// NAN-4953: refuse Vector env-interpolation syntax in every tenant-authored
/// VRL field a save writes (see [`crate::vector_env::reject_vrl_interpolation`]).
/// `None` means "not being written" and is not checked.
pub(super) fn reject_vrl_interpolation(
    fields: &[(&str, Option<&str>)],
) -> Result<(), LogSourceServiceError> {
    for (field, value) in fields {
        if let Some(value) = value {
            crate::vector_env::reject_vrl_interpolation(field, value)
                .map_err(LogSourceServiceError::InvalidVrl)?;
        }
    }
    Ok(())
}

/// NAN-5789: the canonical spelling of an accepted `source_type` (case,
/// aliases such as `s3` / `pubsub` / `http`). Callers validated it with
/// `SourceType::from_str` first; an unexpected value is kept as written.
pub(super) fn canonical_source_type(source_type: &str) -> String {
    crate::log_sources::ingest_transport::canonical(source_type)
        .map(str::to_string)
        .unwrap_or_else(|| source_type.to_string())
}

impl LogSourceService {
    /// NAN-5789: a fetch source must name an existing source configuration
    /// of its own type (drafts included), and a live one a DEPLOYED one
    /// ([`crate::log_sources::source_binding`]). 400 with a field error.
    async fn ensure_source_configuration(
        &self,
        kind: &str,
        source_type: &str,
        dispatch_source_config_id: Option<Uuid>,
        must_be_deployed: bool,
    ) -> Result<(), LogSourceServiceError> {
        crate::log_sources::source_binding::ensure_binding(
            &self.pool,
            kind,
            source_type,
            dispatch_source_config_id,
            must_be_deployed,
        )
        .await
        .map_err(crate::log_sources::LogSourceRepositoryError::from)?
        .map_err(|e| LogSourceServiceError::MissingSourceConfiguration { field: e.field, message: e.message })
    }

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

    pub async fn create(&self, mut new: NewLogSource) -> Result<LogSource, LogSourceServiceError> {
        // Validate source type
        if SourceType::from_str(&new.source_type).is_none() {
            return Err(LogSourceServiceError::InvalidSourceType(
                new.source_type.clone(),
            ));
        }
        // NAN-5789: store the canonical spelling. The renderer classifies on
        // it, so `KAFKA` stored raw would not be treated as the fetch source
        // every check here validated it as.
        new.source_type = canonical_source_type(&new.source_type);

        // The name lands in a generated TOML section/comment header — reject
        // control chars at the boundary, not just via generator escaping (NAN-1371).
        crate::config_safety::validate_config_name(&new.name)
            .map_err(LogSourceServiceError::InvalidSourceConfig)?;

        // NAN-2158: `match_field` is a SQL column identifier, not a value.
        validate_match_field(new.match_field.as_deref())?;

        // NAN-5839: stored canonical (`america/new_york` -> `America/New_York`,
        // `-0500` -> `-05:00`, empty -> `UTC`), so the injected value is the
        // exact spelling the parsers accept.
        new.timezone = normalize_timezone(&new.timezone)?;

        reject_vrl_interpolation(&[
            ("parser_vrl", Some(new.parser_vrl.as_str())),
            ("sampling_exclude_condition", new.sampling_exclude_condition.as_deref()),
        ])?;
        check_sampling_condition(new.sampling_exclude_condition.as_deref())?;

        // NAN-5789: a fetch source without a source configuration cannot
        // render; refuse it here rather than leave it to break every render.
        // A new source is never live (it is created disabled), so its
        // configuration need not be deployed yet.
        self.ensure_source_configuration("log", &new.source_type, new.dispatch_source_config_id, false)
            .await?;

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
        let validation = match self.validate_vrl(&log_source.parser_vrl).await {
            Ok(validation) => validation,
            Err(busy) => return Err(self.mark_validation_pending(log_source.id, busy).await),
        };
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

    /// The parser half of a source's validity. An enrichment source carries
    /// its logic in `normalize_vrl` (checked on its own path), and a stub
    /// source (blank parser, logic in an enabled extension) has no parser to
    /// check. Errors are the validator's messages.
    async fn parser_part_valid(
        &self,
        kind: &str,
        parser_vrl: &str,
        extension_enabled: bool,
        extension_vrl: Option<&str>,
    ) -> Result<Result<(), Vec<String>>, LogSourceServiceError> {
        let stub = parser_vrl.trim().is_empty()
            && extension_enabled
            && extension_vrl.is_some_and(|v| !v.trim().is_empty());
        if kind == "enrichment" || stub {
            return Ok(Ok(()));
        }
        let validation = self.validate_vrl(parser_vrl).await?;
        Ok(if validation.valid {
            Ok(())
        } else {
            Err(validation.errors)
        })
    }

    /// NAN-5401: the source was written but no validation worker freed up in
    /// time. Fail closed (not validated, so it cannot be enabled on a stale
    /// verdict) with a message saying why, and return the retryable error.
    async fn mark_validation_pending(&self, id: Uuid, busy: LogSourceServiceError) -> LogSourceServiceError {
        let note = format!("Validation pending: {busy}");
        if let Err(e) = self.repository().set_validation_status(id, false, Some(&note)).await {
            tracing::warn!(log_source_id = %id, error = %e, "Could not mark the log source validation as pending");
        }
        busy
    }

    /// Update a log source
    pub async fn update(
        &self,
        id: Uuid,
        mut update: UpdateLogSource,
    ) -> Result<LogSource, LogSourceServiceError> {
        // Validate source type if being updated
        if let Some(ref source_type) = update.source_type {
            if SourceType::from_str(source_type).is_none() {
                return Err(LogSourceServiceError::InvalidSourceType(
                    source_type.clone(),
                ));
            }
        }
        // NAN-5789: stored canonical, like create.
        update.source_type = update.source_type.as_deref().map(canonical_source_type);
        // NAN-5839: the timezone, validated and stored canonical like create.
        update.timezone = update.timezone.as_deref().map(normalize_timezone).transpose()?;

        // NAN-5789: when a PUT changes the transport or the binding, or
        // enables the source, the RESULT must still render: a fetch source
        // needs an existing configuration of its own type, and a live one a
        // DEPLOYED one (otherwise the render leaves it out and its ingest
        // stops). A PUT touching none of these (rename, disable) is not
        // checked, so a legacy unbound row can still be disabled or renamed;
        // switching it to "routed" or binding it fixes it.
        if update.source_type.is_some() || update.dispatch_source_config_id.is_some() || update.enabled == Some(true) {
            let current = self.repository().find_by_id(id).await?;
            let source_type = update.source_type.as_deref().unwrap_or(current.source_type.as_str());
            let binding = update.dispatch_source_config_id.or(current.dispatch_source_config_id);
            let live = update.enabled.unwrap_or(current.enabled);
            self.ensure_source_configuration(&current.kind, source_type, binding, live).await?;
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
        reject_vrl_interpolation(&[
            ("parser_vrl", update.parser_vrl.as_deref()),
            ("normalize_vrl", update.normalize_vrl.as_deref()),
            ("extension_vrl", update.extension_vrl.as_deref()),
            ("sampling_exclude_condition", update.sampling_exclude_condition.as_deref()),
        ])?;

        // NAN-5012: the exclude condition is VRL that Vector runs with its
        // full stdlib; it must be a read-only predicate over the parser
        // allowlist.
        check_sampling_condition(update.sampling_exclude_condition.as_deref())?;

        // NAN-5057: enabling a source in the same PUT that saves its VRL must
        // not skip the `enable()` gate. Only the disabled -> enabled
        // transition is checked, so re-sending `enabled: true` for a source
        // that is already enabled keeps working.
        if update.enabled == Some(true) {
            let current = self.repository().find_by_id(id).await?;
            if !current.enabled {
                let parser_vrl = update
                    .parser_vrl
                    .as_deref()
                    .unwrap_or(current.parser_vrl.as_str());
                let extension_vrl = update
                    .extension_vrl
                    .as_deref()
                    .or(current.extension_vrl.as_deref());
                let extension_enabled =
                    update.extension_enabled.unwrap_or(current.extension_enabled);
                let parser_ok = self
                    .parser_part_valid(&current.kind, parser_vrl, extension_enabled, extension_vrl)
                    .await?
                    .is_ok();
                if !parser_ok
                    || check_extension(extension_enabled, extension_vrl).is_err()
                {
                    return Err(LogSourceServiceError::NotValidated);
                }
            }
        }

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

        // If VRL was updated, validate and set the correct status. NAN-5057:
        // the extension runs in the same Vector remap chain, so it is part of
        // the source's validity (an extension-only edit used to leave
        // `validated` untouched).
        let extension_changed =
            update.extension_vrl.is_some() || update.extension_enabled.is_some();
        if update.parser_vrl.is_some() || extension_changed {
            let mut errors = match self
                .parser_part_valid(
                    &log_source.kind,
                    &log_source.parser_vrl,
                    log_source.extension_enabled,
                    log_source.extension_vrl.as_deref(),
                )
                .await
            {
                Ok(verdict) => verdict.err().unwrap_or_default(),
                Err(busy) => return Err(self.mark_validation_pending(id, busy).await),
            };
            if let Err(e) = check_extension(
                log_source.extension_enabled,
                log_source.extension_vrl.as_deref(),
            ) {
                errors.push(e);
            }
            let valid = errors.is_empty();
            let error_msg = (!valid).then(|| errors.join("; "));

            self.repository()
                .set_validation_status(id, valid, error_msg.as_deref())
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
    ///
    /// NAN-5678: batched with every other delete pending at the same time
    /// (see [`Self::delete_many`]), so concurrent deletes cost one render and
    /// one Vector reload, and the work runs to completion even if the caller
    /// stops waiting.
    pub async fn delete(&self, id: Uuid) -> Result<(), LogSourceServiceError> {
        self.delete_many(vec![id])
            .await
            .into_iter()
            .find(|(key, _)| *key == id)
            .map(|(_, result)| result.map(|_deleted| ()))
            .unwrap_or_else(|| Err(LogSourceServiceError::DeploymentFailed("the delete recorded no result".to_string())))
    }

    /// NAN-5678: delete several log sources with ONE config render and ONE
    /// Vector reload. Results are per id, in the order given (duplicates
    /// collapse to the first occurrence).
    ///
    /// Each reload recompiles every deployed parser's VRL, so with ~40 OCSF
    /// sources a reload takes minutes on a cloud vCPU; deleting sources one
    /// call at a time paid that once per source. The ids are handed to the
    /// service's [`ChangeBatcher`](crate::log_sources::change_batch::ChangeBatcher),
    /// which also folds in any other delete pending at the same moment and
    /// runs the batch in its own task: a client that disconnects mid-delete
    /// no longer cancels it between the config write and the row delete.
    ///
    /// NAN-5683: a successful delete carries the deleted source's name
    /// ([`DeletedLogSource`]) so the caller can audit it after the row is gone.
    pub async fn delete_many(&self, ids: Vec<Uuid>) -> Vec<(Uuid, Result<DeletedLogSource, LogSourceServiceError>)> {
        let mut seen = std::collections::HashSet::new();
        let ids: Vec<Uuid> = ids.into_iter().filter(|id| seen.insert(*id)).collect();
        let service = self.clone();
        let runner: crate::log_sources::change_batch::BatchRunner<Uuid, Result<DeletedLogSource, BatchFailure>> =
            std::sync::Arc::new(move |batch: Vec<Uuid>| {
                let service = service.clone();
                Box::pin(async move { service.delete_batch(batch).await })
            });
        let mut results = self.delete_batcher.submit(ids.clone(), runner).await;
        ids.into_iter()
            .map(|id| {
                let result = match results.remove(&id) {
                    Some(Ok(Ok(deleted))) => Ok(deleted),
                    Some(Ok(Err(BatchFailure::NotFound))) => Err(LogSourceServiceError::RepositoryError(
                        crate::log_sources::LogSourceRepositoryError::NotFound(id.to_string()),
                    )),
                    Some(Ok(Err(BatchFailure::Database))) => Err(sanitized_database_error()),
                    Some(Ok(Err(BatchFailure::Failed(message)))) => {
                        Err(LogSourceServiceError::DeploymentFailed(message))
                    }
                    Some(Err(batch_error)) => Err(LogSourceServiceError::DeploymentFailed(batch_error.to_string())),
                    None => Err(LogSourceServiceError::DeploymentFailed("the delete recorded no result".to_string())),
                };
                (id, result)
            })
            .collect()
    }

    /// One batch of [`Self::delete_many`]: render the tree without every
    /// source in `ids` and reload once, deleting the rows in one statement
    /// (after the reload on a single node, before the publish on role split).
    async fn delete_batch(&self, ids: Vec<Uuid>) -> std::collections::HashMap<Uuid, Result<DeletedLogSource, BatchFailure>> {
        let mut results = std::collections::HashMap::new();
        let mut found: Vec<LogSource> = Vec::new();
        for id in ids {
            match self.repository().find_by_id(id).await {
                Ok(log_source) => found.push(log_source),
                Err(crate::log_sources::LogSourceRepositoryError::NotFound(_)) => {
                    results.insert(id, Err(BatchFailure::NotFound));
                }
                Err(e) => {
                    // NAN-2266: logged here, never handed to the client.
                    tracing::error!(log_source_id = %id, error = %e, "could not read a log source to delete");
                    results.insert(id, Err(BatchFailure::Database));
                }
            }
        }
        if found.is_empty() {
            return results;
        }
        let doomed: std::collections::HashSet<Uuid> = found.iter().map(|s| s.id).collect();
        let names: Vec<&str> = found.iter().map(|s| s.name.as_str()).collect();

        // NAN-2305: the active Vector tree is republished BEFORE the rows go,
        // in one locked pass, and the parser TOML is never unlinked on its
        // own. Unlinking first left `_combiner.toml` naming a transform whose
        // file no longer existed, which Vector treats as fatal to the WHOLE
        // config. Regenerating from the surviving sources prunes the orphaned
        // parser files and rewrites the combiner and router in the same pass,
        // so no intermediate state is ever visible on disk.
        //
        // NAN-2310: ALWAYS regenerate, never gate on `deployed`: `update`
        // clears that flag while `_combiner.toml` and `_router.toml` may still
        // name the source, so unlinking alone reproduced the NAN-2296 dangling
        // input. For a never-deployed source this is a no-op that still
        // prunes any stale file.
        {
            let _deploy_guard = self.vector_config.lock_deploys().await;

            // NAN-2305's filter must stay: the rows are deleted AFTER this
            // regeneration on a single node, inside the guard, so they are
            // still present here.
            let parsers: Vec<_> = match self.effective_deployed_parsers().await {
                Ok(parsers) => parsers.into_iter().filter(|parser| !doomed.contains(&parser.id)).collect(),
                // NAN-5789: only a database error is reported as one; any
                // other render-prep failure names itself.
                Err(LogSourceServiceError::RepositoryError(e)) => {
                    tracing::error!(sources = ?names, error = %e, "could not list the deployed log sources for a delete");
                    return fail_all_with(results, &doomed, BatchFailure::Database);
                }
                Err(e) => {
                    tracing::error!(sources = ?names, error = %e, "could not prepare the Vector config for a delete");
                    return fail_all_with(results, &doomed, BatchFailure::Failed(e.to_string()));
                }
            };

            if crate::parsers::VectorConfigManager::generation_delivery_active() {
                // NAN-5678 review: role split renders the published generation
                // from the DATABASE, so the rows must be gone before the
                // publish, or it republishes (and grades) the pre-delete
                // config. Same order as undeploy: database first, then one
                // render and publish of what remains.
                if let Err(failure) = self.delete_rows(&found, &mut results).await {
                    return fail_all_with(results, &doomed, failure);
                }
                if let Err(failure) = self.vector_config.deploy_and_reload_locked_graded(&parsers).await {
                    tracing::error!(
                        sources = ?names,
                        "log source(s) deleted, but the ingest hosts did not confirm the new \
                         generation; the publication reconciler retries: {}",
                        failure.error
                    );
                }
            } else {
                // Single node: config first, rows after. The deploy snapshots
                // the active tree, skips the reload when nothing Vector runs
                // changed (NAN-5611: deleting a never-deployed draft), and
                // restores the snapshot when the write fails or Vector refuses
                // the tree. In those cases the rows stay, so the database and
                // the config still agree and the operator can retry.
                if let Err(failure) = self.vector_config.deploy_and_reload_locked_graded(&parsers).await {
                    if !failure.tree_kept {
                        tracing::error!(
                            sources = ?names,
                            "Refusing to delete log source(s): the Vector config without them was not \
                             applied (restored the previous one): {}",
                            failure.error
                        );
                        return fail_all_with(
                            results,
                            &doomed,
                            BatchFailure::Failed(LogSourceServiceError::VectorConfigError(failure.error).to_string()),
                        );
                    }
                    // Deliberately NOT fatal: the tree without them is written
                    // and coherent; Vector only did not confirm loading it (down
                    // or slow), so the worst case is an unused route until it
                    // next reloads. Blocking deletion behind that is worse.
                    tracing::error!(
                        sources = ?names,
                        "Vector config for deleted log source(s) was written but Vector did not confirm \
                         the reload — it may still be routing them until it next reloads: {}",
                        failure.error
                    );
                }
                // Inside the guard, with the config already republished:
                // dropping the lock first would let a concurrent deploy read a
                // still-present row and put the source straight back into the
                // config. A failed row delete leaves the source out of the
                // config but in the database, so the next deploy restores it
                // and that delete simply did not happen.
                if let Err(failure) = self.delete_rows(&found, &mut results).await {
                    return fail_all_with(results, &doomed, failure);
                }
            }
        }

        for log_source in &found {
            if !matches!(results.get(&log_source.id), Some(Ok(_))) {
                continue;
            }
            // Clean up orphaned routing rules that targeted this log source's
            // source_type. DB only: the next explicit source config deploy
            // regenerates configs without these rules.
            match sqlx::query("DELETE FROM routing_rules WHERE target_source_type = $1")
                .bind(&log_source.source_type)
                .execute(&self.pool)
                .await
            {
                Ok(result) if result.rows_affected() > 0 => {
                    tracing::info!(
                        "Removed {} orphaned routing rule(s) targeting source_type '{}'",
                        result.rows_affected(),
                        log_source.source_type
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to clean up routing rules for source_type '{}': {}",
                        log_source.source_type,
                        e
                    );
                }
                _ => {}
            }
            tracing::info!("Deleted log source '{}' ({})", log_source.name, log_source.id);
        }
        if found.len() > 1 {
            tracing::info!(count = found.len(), "Deleted log sources with one Vector config render and reload");
        }
        results
    }

    /// Delete `found`'s rows in one statement and record each result. An id
    /// the statement did not return was deleted concurrently (not found).
    async fn delete_rows(
        &self,
        found: &[LogSource],
        results: &mut std::collections::HashMap<Uuid, Result<DeletedLogSource, BatchFailure>>,
    ) -> Result<(), BatchFailure> {
        let ids: Vec<Uuid> = found.iter().map(|s| s.id).collect();
        let deleted = self.repository().delete_many(&ids).await.map_err(|e| {
            // NAN-2266: logged here, never handed to the client.
            tracing::error!(error = %e, count = ids.len(), "could not delete log source rows");
            BatchFailure::Database
        })?;
        let deleted: std::collections::HashSet<Uuid> = deleted.into_iter().collect();
        for source in found {
            let outcome = if deleted.contains(&source.id) {
                Ok(DeletedLogSource { name: source.name.clone() })
            } else {
                Err(BatchFailure::NotFound)
            };
            results.insert(source.id, outcome);
        }
        Ok(())
    }
}

/// A log source [`LogSourceService::delete_many`] deleted (NAN-5683): what
/// the caller still needs once the row is gone, i.e. the name its audit
/// row records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedLogSource {
    pub name: String,
}

/// Why one source in a [`LogSourceService::delete_many`] batch was not
/// deleted. Clonable, so one failed render can be reported to every caller
/// whose source was in the batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum BatchFailure {
    NotFound,
    /// A database error, already logged; the caller gets the sanitized
    /// NAN-2266 message, never the driver's text.
    Database,
    /// The Vector config without the source could not be applied.
    Failed(String),
}

/// Every source in `doomed` without a result yet fails with `failure`.
fn fail_all_with(
    mut results: std::collections::HashMap<Uuid, Result<DeletedLogSource, BatchFailure>>,
    doomed: &std::collections::HashSet<Uuid>,
    failure: BatchFailure,
) -> std::collections::HashMap<Uuid, Result<DeletedLogSource, BatchFailure>> {
    for id in doomed {
        results.entry(*id).or_insert_with(|| Err(failure.clone()));
    }
    results
}

/// NAN-2266: the error a database failure maps to, so the API answers with its
/// sanitized "A database error occurred" (the real error is logged where it
/// happened).
fn sanitized_database_error() -> LogSourceServiceError {
    LogSourceServiceError::RepositoryError(crate::log_sources::LogSourceRepositoryError::DatabaseError(
        sqlx::Error::Protocol("a database error occurred while deleting the log source".to_string()),
    ))
}

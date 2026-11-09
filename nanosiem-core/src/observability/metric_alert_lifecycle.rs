// SPDX-License-Identifier: AGPL-3.0-or-later
//! One durable incident per monitor series (NAN-3975). Callers own the
//! transaction. The single-tenant ClickHouse product always passes
//! `tenant: None` (no tenant predicate is emitted); the parameter is kept so the
//! module stays a clean cherry-pick target from main.
use chrono::{DateTime, Utc};
use sqlx::{Postgres, QueryBuilder, Transaction};
use uuid::Uuid;

fn scope<'a>(query: &mut QueryBuilder<'a, Postgres>, tenant: Option<Uuid>) {
    if let Some(tenant) = tenant {
        query.push(" AND tenant_id = ").push_bind(tenant);
    }
}

/// Serialize writers of one monitor's incidents for the rest of the
/// transaction. Held only for the short apply transaction, never across the
/// ClickHouse query (see the scheduler).
pub async fn lock_monitor(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Option<Uuid>,
    monitor: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,3975))")
        .bind(format!("{tenant:?}:{monitor}"))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Workflow state of one open incident row, for keeper selection.
#[derive(Debug, Clone)]
pub struct IncidentWorkflow {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub acknowledged: bool,
    pub assigned: bool,
    /// Linked to a case or incident (`case_id`, `incident_id` or a
    /// `case_alerts` row).
    pub case_linked: bool,
}

/// The duplicate that survives consolidation: the one an analyst has worked
/// (case-linked, then acknowledged/assigned), else the earliest. Closing the
/// row an analyst acknowledged or attached to a case would resurface the
/// incident in triage and strand the case's link.
pub fn choose_keeper(rows: &[IncidentWorkflow]) -> Option<usize> {
    let rank = |r: &IncidentWorkflow| {
        if r.case_linked {
            2
        } else if r.acknowledged || r.assigned {
            1
        } else {
            0
        }
    };
    rows.iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| {
            rank(a)
                .cmp(&rank(b))
                // Earliest wins a tie (max_by keeps the last maximum, so invert).
                .then_with(|| b.created_at.cmp(&a.created_at))
                .then_with(|| b.id.cmp(&a.id))
        })
        .map(|(i, _)| i)
}

/// Optional link schema: the open-core fresh snapshot has neither, the
/// enterprise / legacy schema has `alerts.case_id`, `alerts.incident_id`
/// and `case_alerts`.
struct LinkSchema {
    case_id: bool,
    incident_id: bool,
    #[cfg(feature = "enterprise")]
    case_alerts: bool,
}

#[cfg(feature = "enterprise")]
async fn link_schema(tx: &mut Transaction<'_, Postgres>) -> Result<LinkSchema, sqlx::Error> {
    let (case_id, incident_id, case_alerts): (bool, bool, bool) = sqlx::query_as(
        "SELECT \
           EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' \
                   AND table_name = 'alerts' AND column_name = 'case_id'), \
           EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' \
                   AND table_name = 'alerts' AND column_name = 'incident_id'), \
           to_regclass('public.case_alerts') IS NOT NULL",
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok(LinkSchema {
        case_id,
        incident_id,
        case_alerts,
    })
}

#[cfg(not(feature = "enterprise"))]
async fn link_schema(_tx: &mut Transaction<'_, Postgres>) -> Result<LinkSchema, sqlx::Error> {
    Ok(LinkSchema {
        case_id: false,
        incident_id: false,
    })
}

/// Collapse pre-existing hourly duplicates (left by the old 1h re-arm)
/// without deleting audit history. The caller holds [`lock_monitor`].
///
/// Per duplicated series: keep the worked row ([`choose_keeper`]), merge the
/// others' workflow into it (acknowledgement, assignee, case/incident link,
/// the latest observed payload, the earliest start as `first_seen_at`),
/// repoint their `case_alerts` links to it, then close them with
/// `merged_into` recorded in their payload.
pub async fn reconcile(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Option<Uuid>,
    monitor: Uuid,
) -> Result<(), sqlx::Error> {
    let mut q = QueryBuilder::<Postgres>::new(
        "SELECT source_id FROM alerts WHERE kind='metric_monitor' AND status IN ('new','acknowledged') \
         AND starts_with(source_id, ",
    );
    q.push_bind(format!("{monitor}:")).push(")");
    scope(&mut q, tenant);
    q.push(" GROUP BY source_id HAVING count(*) > 1");
    let duplicated: Vec<String> = q.build_query_scalar().fetch_all(&mut **tx).await?;
    if duplicated.is_empty() {
        return Ok(());
    }
    let links = link_schema(tx).await?;
    for source in duplicated {
        consolidate(tx, tenant, &source, &links).await?;
    }
    Ok(())
}

async fn consolidate(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Option<Uuid>,
    source: &str,
    links: &LinkSchema,
) -> Result<(), sqlx::Error> {
    let case_col = if links.case_id { "case_id IS NOT NULL" } else { "false" };
    let incident_col = if links.incident_id { "incident_id IS NOT NULL" } else { "false" };
    #[cfg(feature = "enterprise")]
    let link_col = if links.case_alerts {
        "EXISTS (SELECT 1 FROM case_alerts ca WHERE ca.alert_id = alerts.id)"
    } else {
        "false"
    };
    #[cfg(not(feature = "enterprise"))]
    let link_col = "false";
    let mut q = QueryBuilder::<Postgres>::new(format!(
        "SELECT id, created_at, status = 'acknowledged', assigned_to IS NOT NULL, \
         ({case_col} OR {incident_col} OR {link_col}) \
         FROM alerts WHERE kind='metric_monitor' AND status IN ('new','acknowledged') AND source_id = "
    ));
    q.push_bind(source.to_owned());
    scope(&mut q, tenant);
    q.push(" ORDER BY created_at, id FOR UPDATE");
    let rows: Vec<(Uuid, Option<DateTime<Utc>>, bool, bool, bool)> =
        q.build_query_as().fetch_all(&mut **tx).await?;
    let workflow: Vec<IncidentWorkflow> = rows
        .iter()
        .map(|(id, created_at, acknowledged, assigned, case_linked)| IncidentWorkflow {
            id: *id,
            created_at: created_at.unwrap_or(DateTime::<Utc>::MIN_UTC),
            acknowledged: *acknowledged,
            assigned: *assigned,
            case_linked: *case_linked,
        })
        .collect();
    let Some(keeper_idx) = choose_keeper(&workflow) else {
        return Ok(());
    };
    if workflow.len() < 2 {
        return Ok(());
    }
    let keeper = workflow[keeper_idx].id;
    let all: Vec<Uuid> = workflow.iter().map(|w| w.id).collect();
    let dups: Vec<Uuid> = all.iter().copied().filter(|id| *id != keeper).collect();

    // Merge workflow + payload into the keeper. Every value comes from rows of
    // this one series (`all`), most recent first.
    let mut merge = String::from(
        "UPDATE alerts k SET \
           status = CASE WHEN EXISTS (SELECT 1 FROM alerts d WHERE d.id = ANY($2) AND d.status = 'acknowledged') \
                    THEN 'acknowledged' ELSE k.status END, \
           acknowledged_by = COALESCE(k.acknowledged_by, (SELECT d.acknowledged_by FROM alerts d \
                    WHERE d.id = ANY($2) AND d.acknowledged_by IS NOT NULL \
                    ORDER BY d.acknowledged_at DESC NULLS LAST LIMIT 1)), \
           acknowledged_at = COALESCE(k.acknowledged_at, (SELECT d.acknowledged_at FROM alerts d \
                    WHERE d.id = ANY($2) AND d.acknowledged_at IS NOT NULL \
                    ORDER BY d.acknowledged_at DESC LIMIT 1)), \
           assigned_to = COALESCE(k.assigned_to, (SELECT d.assigned_to FROM alerts d \
                    WHERE d.id = ANY($2) AND d.assigned_to IS NOT NULL \
                    ORDER BY d.created_at DESC LIMIT 1)), \
           matched_events = jsonb_set( \
             (SELECT d.matched_events FROM alerts d WHERE d.id = ANY($2) \
              ORDER BY COALESCE((d.matched_events->0->>'evaluated_at')::timestamptz, d.created_at) DESC, d.id DESC \
              LIMIT 1), \
             '{0,first_seen_at}', \
             to_jsonb((SELECT min(d.created_at) FROM alerts d WHERE d.id = ANY($2))))",
    );
    for (enabled, col) in [(links.case_id, "case_id"), (links.incident_id, "incident_id")] {
        if enabled {
            merge.push_str(&format!(
                ", {col} = COALESCE(k.{col}, (SELECT d.{col} FROM alerts d WHERE d.id = ANY($2) \
                 AND d.{col} IS NOT NULL ORDER BY d.created_at DESC LIMIT 1))"
            ));
        }
    }
    merge.push_str(" WHERE k.id = $1");
    sqlx::query(&merge)
        .bind(keeper)
        .bind(&all)
        .execute(&mut **tx)
        .await?;

    #[cfg(feature = "enterprise")]
    if links.case_alerts {
        // Repoint the duplicates' case links to the keeper (one link per
        // case; primary if any duplicate was primary), then drop theirs.
        sqlx::query(
            "INSERT INTO case_alerts (case_id, alert_id, added_at, added_by, is_primary) \
             SELECT case_id, $1, min(added_at), (array_agg(added_by ORDER BY added_at))[1], bool_or(is_primary) \
             FROM case_alerts WHERE alert_id = ANY($2) GROUP BY case_id \
             ON CONFLICT (case_id, alert_id) DO UPDATE \
               SET is_primary = case_alerts.is_primary OR EXCLUDED.is_primary",
        )
        .bind(keeper)
        .bind(&dups)
        .execute(&mut **tx)
        .await?;
        sqlx::query("DELETE FROM case_alerts WHERE alert_id = ANY($1)")
            .bind(&dups)
            .execute(&mut **tx)
            .await?;
    }

    // A closed duplicate no longer counts toward the keeper's case/incident.
    for (enabled, col) in [(links.case_id, "case_id"), (links.incident_id, "incident_id")] {
        if enabled {
            sqlx::query(&format!(
                "UPDATE alerts d SET {col} = NULL FROM alerts k \
                 WHERE k.id = $1 AND d.id = ANY($2) AND d.{col} = k.{col}"
            ))
            .bind(keeper)
            .bind(&dups)
            .execute(&mut **tx)
            .await?;
        }
    }

    sqlx::query(
        "UPDATE alerts SET status = 'closed', closed_at = now(), \
         matched_events = jsonb_set(matched_events, '{0,merged_into}', to_jsonb($1::text)) \
         WHERE id = ANY($2)",
    )
    .bind(keeper.to_string())
    .bind(&dups)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Apply a known sample. No-data is deliberately handled by the caller: it
/// cannot open or resolve an incident. Returns an id only for a new incident,
/// so updates never send repeated opening notifications.
pub async fn observe(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Option<Uuid>,
    source: &str,
    breaching: bool,
    payload: &serde_json::Value,
    now: DateTime<Utc>,
) -> Result<Option<Uuid>, sqlx::Error> {
    let mut q = QueryBuilder::<Postgres>::new("UPDATE alerts SET matched_events = ");
    q.push_bind(payload.clone());
    if !breaching {
        q.push(", status='closed', closed_at=").push_bind(now);
    }
    q.push(" WHERE kind='metric_monitor' AND status IN ('new','acknowledged') AND source_id=")
        .push_bind(source.to_owned());
    scope(&mut q, tenant);
    // A slow older evaluation must not overwrite a newer observation/recovery.
    q.push(" AND COALESCE((matched_events->0->>'evaluated_at')::timestamptz, created_at) <= ")
        .push_bind(now);
    let updated = q.build().execute(&mut **tx).await?.rows_affected();
    if !breaching || updated > 0 {
        return Ok(None);
    }
    // Includes closed incidents: an older leader must not reopen after recovery.
    let mut q = QueryBuilder::<Postgres>::new(
        "SELECT EXISTS(SELECT 1 FROM alerts WHERE kind='metric_monitor' AND source_id=",
    );
    q.push_bind(source.to_owned());
    scope(&mut q, tenant);
    q.push(" AND COALESCE((matched_events->0->>'evaluated_at')::timestamptz, created_at) >= ")
        .push_bind(now)
        .push(")");
    if q.build_query_scalar::<bool>().fetch_one(&mut **tx).await? {
        return Ok(None);
    }
    let id = Uuid::new_v4();
    let mut q = QueryBuilder::<Postgres>::new(
        "INSERT INTO alerts (id,kind,rule_id,source_id,severity,matched_events,created_at",
    );
    if tenant.is_some() {
        q.push(",tenant_id");
    }
    q.push(") VALUES (")
        .push_bind(id)
        .push(",'metric_monitor',NULL,")
        .push_bind(source.to_owned())
        .push(",'high',")
        .push_bind(payload.clone())
        .push(",")
        .push_bind(now);
    if let Some(tenant) = tenant {
        q.push(",").push_bind(tenant);
    }
    q.push(")").build().execute(&mut **tx).await?;
    Ok(Some(id))
}

/// The old empty-instance incident represents a fleet aggregate, not any one
/// node. Retire it once labelled samples arrive; never assign its history to an
/// arbitrary node. Its original start and payload remain available for audit.
pub async fn retire_unlabelled(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Option<Uuid>,
    monitor: Uuid,
    now: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    let mut q = QueryBuilder::<Postgres>::new("UPDATE alerts SET status='closed', closed_at=");
    q.push_bind(now).push(", matched_events=jsonb_set(matched_events, '{0,resolution_reason}', \
        to_jsonb('replaced_by_labelled_series'::text)) WHERE kind='metric_monitor' AND status IN ('new','acknowledged') AND source_id=")
        .push_bind(format!("{monitor}:"));
    scope(&mut q, tenant);
    q.push(" AND COALESCE((matched_events->0->>'evaluated_at')::timestamptz, created_at) <= ")
        .push_bind(now);
    q.build().execute(&mut **tx).await?;
    Ok(())
}

/// Durable per-(monitor, series) evaluation cursor (migration 292). Records
/// this evaluation — value, breach, no-data — and returns `true` only when it
/// is newer than the last one recorded. A `false` result means a newer
/// evaluation (possibly a healthy one that touched no incident) already
/// applied, so the caller must not open, update or resolve anything with
/// this stale result. The caller holds [`lock_monitor`].
pub async fn advance_cursor(
    tx: &mut Transaction<'_, Postgres>,
    monitor: Uuid,
    series_key: &str,
    value: Option<f64>,
    breaching: bool,
    definition_updated_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    let applied: Option<i32> = sqlx::query_scalar(
        "INSERT INTO observability_metric_monitor_state \
           (monitor_id, series_key, value, breaching, no_data, definition_updated_at, evaluated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (monitor_id, series_key) DO UPDATE SET \
           value = EXCLUDED.value, breaching = EXCLUDED.breaching, no_data = EXCLUDED.no_data, \
           definition_updated_at = EXCLUDED.definition_updated_at, evaluated_at = EXCLUDED.evaluated_at \
         WHERE observability_metric_monitor_state.evaluated_at < EXCLUDED.evaluated_at \
         RETURNING 1",
    )
    .bind(monitor)
    .bind(series_key)
    .bind(value)
    .bind(breaching)
    .bind(value.is_none())
    .bind(definition_updated_at)
    .bind(now)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(applied.is_some())
}

/// Advance the monitor-wide evaluation generation to `now` (migration 295).
/// Returns `false` when an evaluation at or after `now` was already applied —
/// the caller must then write nothing. The caller holds [`lock_monitor`].
pub async fn advance_generation(
    tx: &mut Transaction<'_, Postgres>,
    monitor: Uuid,
    now: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    let applied: Option<i32> = sqlx::query_scalar(
        "INSERT INTO observability_metric_monitor_generation (monitor_id, evaluated_at) \
         VALUES ($1, $2) \
         ON CONFLICT (monitor_id) DO UPDATE SET evaluated_at = EXCLUDED.evaluated_at \
         WHERE observability_metric_monitor_generation.evaluated_at < EXCLUDED.evaluated_at \
         RETURNING 1",
    )
    .bind(monitor)
    .bind(now)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(applied.is_some())
}

/// A newly opened incident, to notify once the apply transaction committed.
#[derive(Debug, Clone)]
pub struct IncidentOpened {
    pub id: Uuid,
    /// Webhook entity: the series, or the monitor's service when ungrouped.
    pub entity: Option<String>,
    pub payload: serde_json::Value,
}

/// Apply one monitor evaluation (`results` from the ClickHouse query, taken at
/// `now`) in a SHORT transaction: serialize this monitor's writers, collapse
/// legacy duplicates, retire the unlabelled fleet incident once labelled
/// series report, then per series advance the durable cursor and — only when
/// this result is the newest — open, update or resolve its incident. The
/// ClickHouse query must already be finished: no PostgreSQL transaction or
/// lock is held across it. Returns the incidents opened (notify after this
/// returns; updates never re-notify).
pub async fn apply_evaluation(
    pool: &sqlx::PgPool,
    monitor: &super::MetricMonitor,
    results: Vec<(String, Option<f64>)>,
    now: DateTime<Utc>,
) -> Result<Vec<IncidentOpened>, sqlx::Error> {
    use super::eval::{metric_breach, metric_monitor_source_id, metric_payload};
    let mut tx = pool.begin().await?;
    lock_monitor(&mut tx, None, monitor.id).await?;
    // Monitor-wide generation fence (migration 295): every result set —
    // including an empty one — must be newer than the last one applied, or it
    // is dropped whole. Holding the monitor lock, every write below therefore
    // belongs to the current generation: an older evaluation cannot open an
    // incident for a series a newer (possibly empty) result never saw.
    if !advance_generation(&mut tx, monitor.id, now).await? {
        tx.commit().await?;
        return Ok(Vec::new());
    }
    reconcile(&mut tx, None, monitor.id).await?;

    // A grouped monitor that now reports labelled series retires the legacy
    // empty-series incident (a fleet aggregate, not any one node).
    if monitor.group_by.is_some()
        && results
            .iter()
            .any(|(key, value)| !key.is_empty() && value.is_some())
    {
        retire_unlabelled(&mut tx, None, monitor.id, now).await?;
    }
    // NAN-3894: state is the current series inventory, not an unbounded
    // history. Retire series this evaluation no longer returns once they are a
    // day old: well past any in-flight evaluation, so the per-series cursor
    // still fences slow evaluators.
    let keys: Vec<&str> = results.iter().map(|(key, _)| key.as_str()).collect();
    sqlx::query(
        "DELETE FROM observability_metric_monitor_state \
          WHERE monitor_id = $1 AND evaluated_at < $2 - INTERVAL '1 day' \
            AND NOT (series_key = ANY($3))",
    )
    .bind(monitor.id)
    .bind(now)
    .bind(&keys)
    .execute(&mut *tx)
    .await?;
    // An evaluation that returned no series at all is still an evaluation:
    // record it as no-data on the empty key so the console shows "No data"
    // rather than "Awaiting evaluation". No incident is touched.
    if results.is_empty() {
        advance_cursor(&mut tx, monitor.id, "", None, false, monitor.updated_at, now).await?;
    }
    let mut opened = Vec::new();
    for (series_key, value) in results {
        // A grouped monitor's unlabelled (empty-key) rows are not a series.
        if monitor.group_by.is_some() && series_key.is_empty() {
            continue;
        }
        let value = value.filter(|v| v.is_finite());
        let breaching = metric_breach(monitor, value);
        // Record the evaluation (no-data included); skip a result older than
        // one already applied — e.g. a slow evaluator across a jobs leader
        // failover must not reopen after a newer recovery.
        if !advance_cursor(
            &mut tx,
            monitor.id,
            &series_key,
            value,
            breaching,
            monitor.updated_at,
            now,
        )
        .await?
        {
            continue;
        }
        // O13: no-data can neither open nor resolve an incident.
        let Some(value) = value else {
            continue;
        };
        let source = metric_monitor_source_id(monitor.id, &series_key);
        let payload = metric_payload(monitor, &series_key, value, now);
        if let Some(id) = observe(&mut tx, None, &source, breaching, &payload, now).await? {
            tracing::info!(
                monitor = %monitor.name,
                series = %series_key,
                value,
                threshold = monitor.threshold,
                comparator = monitor.comparator.as_str(),
                "Metric-monitor breach — incident opened"
            );
            let entity = if series_key.is_empty() {
                monitor.service_name.clone()
            } else {
                Some(series_key)
            };
            opened.push(IncidentOpened { id, entity, payload });
        }
    }
    tx.commit().await?;
    Ok(opened)
}

// SPDX-License-Identifier: AGPL-3.0-or-later
//! One durable incident per monitor series. Callers own the transaction; hosted
//! callers must supply the attested tenant and keep notification outbox writes
//! in that same transaction.
use chrono::{DateTime, Utc};
use sqlx::{Postgres, QueryBuilder, Transaction};
use uuid::Uuid;

fn scope<'a>(query: &mut QueryBuilder<'a, Postgres>, tenant: Option<Uuid>) {
    if let Some(tenant) = tenant {
        query.push(" AND tenant_id = ").push_bind(tenant);
    }
}

/// Collapse pre-existing hourly duplicates without deleting audit history.
/// Keep the earliest start and the latest observed payload. Called even on
/// no-data windows, so a restart safely repairs existing incidents.
pub async fn reconcile(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Option<Uuid>,
    monitor: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,3975))")
        .bind(format!("{tenant:?}:{monitor}"))
        .execute(&mut **tx)
        .await?;
    let mut q = QueryBuilder::<Postgres>::new(
        "WITH ranked AS (SELECT id, first_value(id) OVER (PARTITION BY source_id ORDER BY created_at,id) AS keeper, \
         first_value(matched_events) OVER (PARTITION BY source_id ORDER BY COALESCE((matched_events->0->>'evaluated_at')::timestamptz, created_at) DESC,id DESC) AS latest \
         FROM alerts WHERE kind='metric_monitor' AND status IN ('new','acknowledged') AND starts_with(source_id, ",
    );
    q.push_bind(format!("{monitor}:")).push(")");
    scope(&mut q, tenant);
    q.push(") UPDATE alerts a SET matched_events = CASE WHEN a.id=r.keeper THEN r.latest ELSE a.matched_events END, \
        status=CASE WHEN a.id=r.keeper THEN a.status ELSE 'closed' END, \
        closed_at=CASE WHEN a.id=r.keeper THEN a.closed_at ELSE now() END \
        FROM ranked r WHERE a.id=r.id AND (a.id<>r.keeper OR a.matched_events IS DISTINCT FROM r.latest)");
    // Repeat the tenant fence on the mutation, not just its input CTE.
    if let Some(tenant) = tenant {
        q.push(" AND a.tenant_id = ").push_bind(tenant);
    }
    q.build().execute(&mut **tx).await?;
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

/// Fix only the shipped node definitions; leave custom fleet-wide monitors alone.
pub async fn repair_default_grouping(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    let mut q = QueryBuilder::<Postgres>::new("UPDATE observability_metric_monitors SET group_by='instance', updated_at=now() \
        WHERE COALESCE(group_by,'')='' AND ((metric_name='node_filesystem_avail_bytes' AND name IN \
        ('Node disk low (<10 GiB free on /)', 'Node disk low (< 10 GiB free on /)')) OR \
        (metric_name='node_pressure_cpu_waiting_seconds_total' AND name='Node CPU saturated (PSI waiting > 50%)'))");
    scope(&mut q, tenant);
    q.build().execute(&mut **tx).await?;
    // Repair the exact shipped absolute threshold, including already-grouped
    // definitions. Preserve custom names/thresholds and all tenant fences.
    let mut q = QueryBuilder::<Postgres>::new("UPDATE observability_metric_monitors SET name='Node disk low (<10% free on /)', \
        metric_name='node_filesystem_avail_ratio', agg='min', threshold=0.1, comparator='lt', group_by='instance', \
        filters=COALESCE((SELECT jsonb_agg(f) FROM jsonb_array_elements(filters) f WHERE f->>'key'<>'mountpoint'), '[]'::jsonb) \
          || '[{\"key\":\"mountpoint\",\"value\":\"/\"}]'::jsonb, updated_at=now() \
        WHERE metric_name='node_filesystem_avail_bytes' AND threshold=10737418240 AND comparator='lt' \
        AND name IN ('Node disk low (<10 GiB free on /)', 'Node disk low (< 10 GiB free on /)')");
    scope(&mut q, tenant);
    q.build().execute(&mut **tx).await?;
    Ok(())
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

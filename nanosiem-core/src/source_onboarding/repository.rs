// SPDX-License-Identifier: AGPL-3.0-or-later
//! All statements carry the server-established tenant; hosted callers must
//! supply a signed transaction, never the control-plane pool.
use super::*;
use sqlx::{Postgres, Transaction};
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub group_by: String,
    pub complete_gate: bool,
    pub auto_suggest: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            group_by: "wave".into(),
            complete_gate: true,
            auto_suggest: true,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    pub waves: Vec<Wave>,
    pub sources: Vec<PlannedSource>,
    pub settings: Settings,
}
pub struct SourceOnboardingRepository;
impl SourceOnboardingRepository {
    pub async fn read(
        tx: &mut Transaction<'_, Postgres>,
        tenant: Uuid,
    ) -> Result<Plan, sqlx::Error> {
        let waves:Vec<sqlx::types::Json<Wave>>=sqlx::query_scalar("SELECT jsonb_build_object('id',id,'name',name,'target',target,'order',sort_order) FROM source_onboarding_waves WHERE tenant_id=$1 ORDER BY sort_order,id").bind(tenant).fetch_all(&mut **tx).await?;
        let rows:Vec<sqlx::types::Json<PlannedSource>>=sqlx::query_scalar("SELECT jsonb_build_object('id',id,'name',name,'vendor',vendor,'expectedType',expected_type,'waveId',wave_id,'priority',priority,'owner',owner,'target',target,'notes',notes,'linkedLogSourceId',linked_log_source_id,'dismissedLogSourceIds',dismissed_log_source_ids,'completed',completed,'completedAt',completed_at,'completedBy',completed_by) FROM source_onboarding_planned_sources WHERE tenant_id=$1 ORDER BY priority,name,id").bind(tenant).fetch_all(&mut **tx).await?;
        let settings:Option<sqlx::types::Json<Settings>>=sqlx::query_scalar("SELECT jsonb_build_object('groupBy',group_by,'completeGate',complete_gate,'autoSuggest',auto_suggest) FROM source_onboarding_settings WHERE tenant_id=$1").bind(tenant).fetch_optional(&mut **tx).await?;
        Ok(Plan {
            waves: waves.into_iter().map(|w| w.0).collect(),
            sources: rows.into_iter().map(|r| r.0).collect(),
            settings: settings.map(|s| s.0).unwrap_or_default(),
        })
    }
    pub async fn lock(tx: &mut Transaction<'_, Postgres>, tenant: Uuid) -> Result<(), sqlx::Error> {
        // Serializes preview commits, link uniqueness, wave deletion and settings.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,3684))")
            .bind(tenant.to_string())
            .execute(&mut **tx)
            .await?;
        Ok(())
    }
    pub async fn save_wave(
        tx: &mut Transaction<'_, Postgres>,
        tenant: Uuid,
        w: &Wave,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO source_onboarding_waves(tenant_id,id,name,target,sort_order) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,id) DO UPDATE SET name=excluded.name,target=excluded.target,sort_order=excluded.sort_order").bind(tenant).bind(w.id).bind(&w.name).bind(w.target).bind(w.order).execute(&mut **tx).await?;
        Ok(())
    }
    pub async fn delete_wave(
        tx: &mut Transaction<'_, Postgres>,
        tenant: Uuid,
        id: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE source_onboarding_planned_sources SET wave_id=NULL WHERE tenant_id=$1 AND wave_id=$2").bind(tenant).bind(id).execute(&mut **tx).await?;
        sqlx::query("DELETE FROM source_onboarding_waves WHERE tenant_id=$1 AND id=$2")
            .bind(tenant)
            .bind(id)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }
    pub async fn save_source(
        tx: &mut Transaction<'_, Postgres>,
        tenant: Uuid,
        p: &PlannedSource,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO source_onboarding_planned_sources(tenant_id,id,name,vendor,expected_type,wave_id,priority,owner,target,notes,linked_log_source_id,dismissed_log_source_ids,completed,completed_at,completed_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) ON CONFLICT(tenant_id,id) DO UPDATE SET name=excluded.name,vendor=excluded.vendor,expected_type=excluded.expected_type,wave_id=excluded.wave_id,priority=excluded.priority,owner=excluded.owner,target=excluded.target,notes=excluded.notes,linked_log_source_id=excluded.linked_log_source_id,dismissed_log_source_ids=excluded.dismissed_log_source_ids,completed=excluded.completed,completed_at=excluded.completed_at,completed_by=excluded.completed_by")
   .bind(tenant).bind(p.id).bind(&p.name).bind(&p.vendor).bind(&p.expected_type).bind(p.wave_id).bind(p.priority).bind(&p.owner).bind(p.target).bind(&p.notes).bind(p.linked_log_source_id).bind(&p.dismissed_log_source_ids).bind(p.completed).bind(p.completed_at).bind(p.completed_by).execute(&mut **tx).await?;
        Ok(())
    }
    pub async fn delete_source(
        tx: &mut Transaction<'_, Postgres>,
        tenant: Uuid,
        id: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM source_onboarding_planned_sources WHERE tenant_id=$1 AND id=$2")
            .bind(tenant)
            .bind(id)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }
    pub async fn save_settings(
        tx: &mut Transaction<'_, Postgres>,
        tenant: Uuid,
        s: &Settings,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO source_onboarding_settings(tenant_id,group_by,complete_gate,auto_suggest) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id) DO UPDATE SET group_by=excluded.group_by,complete_gate=excluded.complete_gate,auto_suggest=excluded.auto_suggest").bind(tenant).bind(&s.group_by).bind(s.complete_gate).bind(s.auto_suggest).execute(&mut **tx).await?;
        Ok(())
    }
}

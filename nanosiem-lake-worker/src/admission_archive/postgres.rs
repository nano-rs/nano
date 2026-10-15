// SPDX-License-Identifier: AGPL-3.0-or-later
//! Execute-only, LOGIN-bound archive authority (migration 9001240).
use super::*;

pub struct PostgresRetentionAuthority {
    pool: sqlx::PgPool,
}

impl PostgresRetentionAuthority {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    async fn transition(
        &self,
        tenant: Uuid,
        identity: &str,
        operation: &str,
        descriptor: Option<Vec<u8>>,
        publication: Option<serde_json::Value>,
        reference: Option<Uuid>,
    ) -> Result<serde_json::Value> {
        let value = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            sqlx::query_scalar::<_, serde_json::Value>(
                "SELECT nano_shared.admission_archive_transition($1,$2,$3,$4,$5,$6)",
            )
            .bind(tenant)
            .bind(identity)
            .bind(operation)
            .bind(descriptor)
            .bind(publication)
            .bind(reference)
            .fetch_one(&self.pool),
        )
        .await
        .context("archive authority timeout")??;
        Ok(value)
    }

    pub async fn release_publication(&self, tenant: Uuid, identity: &str) -> Result<()> {
        self.transition(tenant, identity, "release_publication", None, None, None)
            .await?;
        Ok(())
    }

    /// Logical retirement is not permission for provider deletion.
    pub async fn retire(&self, tenant: Uuid, identity: &str) -> Result<()> {
        self.transition(tenant, identity, "retire", None, None, None)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl RetentionAuthority for PostgresRetentionAuthority {
    async fn reserve(&self, descriptor: &Descriptor) -> Result<()> {
        self.transition(
            descriptor.tenant_id,
            &descriptor.sha256()?,
            "reserve",
            Some(descriptor.encode()?),
            None,
            None,
        )
        .await?;
        Ok(())
    }
    async fn publish(&self, publication: &Publication) -> Result<()> {
        self.transition(
            publication.descriptor.tenant_id,
            &publication.validate()?,
            "publish",
            None,
            Some(serde_json::to_value(publication)?),
            None,
        )
        .await?;
        Ok(())
    }
    async fn retain(&self, tenant: Uuid, identity: &str, reference: Uuid) -> Result<Publication> {
        if !digest_valid(identity) || reference.is_nil() {
            bail!("invalid archive reference");
        }
        let publication: Publication = serde_json::from_value(
            self.transition(tenant, identity, "retain", None, None, Some(reference))
                .await?,
        )?;
        if publication.validate()? != identity || publication.descriptor.tenant_id != tenant {
            bail!("archive authority returned wrong identity");
        }
        Ok(publication)
    }
    async fn release(&self, tenant: Uuid, identity: &str, reference: Uuid) -> Result<()> {
        self.transition(tenant, identity, "release", None, None, Some(reference))
            .await?;
        Ok(())
    }
}

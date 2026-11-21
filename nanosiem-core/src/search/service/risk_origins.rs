// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5697: finding-origin manifests for `dataset=risk` detection rows.

use super::SearchService;
use crate::risk::clickhouse_sql::{risk_origin_query, RiskFindingsSource, RiskOriginRow};

impl SearchService {
    /// The distinct finding origins behind risk-dataset rows since
    /// `horizon_start_us`, per listed entity or over the whole window
    /// (`entities = None`). See [`risk_origin_query`]. Runs as the system
    /// (unrestricted): it attributes rows, it never serves them to a viewer.
    ///
    /// An `Err` means the provenance is unknown; the caller fails closed.
    pub(crate) async fn risk_finding_origins(
        &self,
        horizon_start_us: i64,
        entities: Option<&[String]>,
    ) -> Result<Vec<RiskOriginRow>, String> {
        let client = self
            .ch_client
            .as_ref()
            .ok_or_else(|| "no ClickHouse client".to_string())?;
        let source = RiskFindingsSource::resolve(self.table_names.is_clustered());
        risk_origin_query(&source, horizon_start_us, entities)
            .to_clickhouse_query(client)
            .fetch_all::<RiskOriginRow>()
            .await
            .map_err(|e| e.to_string())
    }
}

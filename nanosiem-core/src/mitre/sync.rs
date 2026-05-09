// SPDX-License-Identifier: AGPL-3.0-or-later

//! MITRE ATT&CK data synchronization from GitHub

use std::collections::HashMap;
use tracing::{info, warn};

use crate::mitre::repository::MitreRepository;
use crate::mitre::types::{MitreTactic, MitreTechnique, StixBundle, StixObject};

const MITRE_CTI_URL: &str =
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";

/// Service for syncing MITRE ATT&CK data
pub struct MitreSync {
    repository: MitreRepository,
}

impl MitreSync {
    pub fn new(repository: MitreRepository) -> Self {
        Self { repository }
    }

    /// Sync MITRE ATT&CK data from GitHub
    pub async fn sync(&self) -> Result<(i32, i32), Box<dyn std::error::Error + Send + Sync>> {
        info!("Fetching MITRE ATT&CK data from GitHub...");

        // Fetch the STIX bundle
        let response = reqwest::get(MITRE_CTI_URL).await?;
        let bundle: StixBundle = response.json().await?;

        info!("Parsing {} STIX objects...", bundle.objects.len());

        // Build a map of short_name -> tactic_id for technique parsing
        let mut tactic_map: HashMap<String, String> = HashMap::new();
        let mut tactics: Vec<MitreTactic> = Vec::new();
        let mut techniques: Vec<MitreTechnique> = Vec::new();

        // First pass: extract tactics
        for obj in &bundle.objects {
            if obj.object_type == "x-mitre-tactic" {
                if let Some(tactic) = self.parse_tactic(obj) {
                    tactic_map.insert(tactic.short_name.clone(), tactic.id.clone());
                    tactics.push(tactic);
                }
            }
        }

        // Second pass: extract techniques
        for obj in &bundle.objects {
            if obj.object_type == "attack-pattern" {
                if let Some(technique) = self.parse_technique(obj, &tactic_map) {
                    techniques.push(technique);
                }
            }
        }

        // Sort techniques: parents first, then sub-techniques, so FK constraints are satisfied
        techniques.sort_by_key(|t| t.is_subtechnique);

        info!(
            "Found {} tactics and {} techniques",
            tactics.len(),
            techniques.len()
        );

        // Store in database
        for tactic in &tactics {
            if let Err(e) = self.repository.upsert_tactic(tactic).await {
                warn!("Failed to upsert tactic {}: {}", tactic.id, e);
            }
        }

        for technique in &techniques {
            if let Err(e) = self.repository.upsert_technique(technique).await {
                warn!("Failed to upsert technique {}: {}", technique.id, e);
            }
        }

        // Record sync metadata
        self.repository
            .record_sync(
                Some("enterprise-attack"),
                techniques.len() as i32,
                tactics.len() as i32,
            )
            .await?;

        info!("MITRE ATT&CK sync complete");

        Ok((tactics.len() as i32, techniques.len() as i32))
    }

    /// Parse a STIX tactic object
    fn parse_tactic(&self, obj: &StixObject) -> Option<MitreTactic> {
        let name = obj.name.as_ref()?;
        let short_name = obj.x_mitre_shortname.as_ref()?;

        // Get external ID (TA####)
        let external_id = obj.external_references.as_ref().and_then(|refs| {
            refs.iter()
                .find(|r| r.source_name.as_deref() == Some("mitre-attack"))
                .and_then(|r| r.external_id.clone())
        })?;

        let url = obj.external_references.as_ref().and_then(|refs| {
            refs.iter()
                .find(|r| r.source_name.as_deref() == Some("mitre-attack"))
                .and_then(|r| r.url.clone())
        });

        // Truncate description to first paragraph
        let description = obj
            .description
            .as_ref()
            .map(|d| d.split("\n\n").next().unwrap_or(d).to_string());

        Some(MitreTactic {
            id: external_id,
            name: name.clone(),
            short_name: short_name.clone(),
            description,
            url,
        })
    }

    /// Parse a STIX technique object
    fn parse_technique(
        &self,
        obj: &StixObject,
        tactic_map: &HashMap<String, String>,
    ) -> Option<MitreTechnique> {
        // Skip deprecated/revoked techniques
        if obj.x_mitre_deprecated == Some(true) || obj.revoked == Some(true) {
            return None;
        }

        let name = obj.name.as_ref()?;

        // Get external ID (T####)
        let external_id = obj.external_references.as_ref().and_then(|refs| {
            refs.iter()
                .find(|r| r.source_name.as_deref() == Some("mitre-attack"))
                .and_then(|r| r.external_id.clone())
        })?;

        let url = obj.external_references.as_ref().and_then(|refs| {
            refs.iter()
                .find(|r| r.source_name.as_deref() == Some("mitre-attack"))
                .and_then(|r| r.url.clone())
        });

        // Get associated tactics from kill chain phases
        let tactic_ids: Vec<String> = obj
            .kill_chain_phases
            .as_ref()
            .map(|phases| {
                phases
                    .iter()
                    .filter(|p| p.kill_chain_name.as_deref() == Some("mitre-attack"))
                    .filter_map(|p| p.phase_name.as_ref())
                    .filter_map(|phase_name| tactic_map.get(phase_name).cloned())
                    .collect()
            })
            .unwrap_or_default();

        let is_subtechnique = obj.x_mitre_is_subtechnique.unwrap_or(false);
        let parent_id = if is_subtechnique {
            external_id.split('.').next().map(|s| s.to_string())
        } else {
            None
        };

        // Truncate description to first paragraph (max 500 chars)
        let description = obj.description.as_ref().map(|d| {
            let first_para = d.split("\n\n").next().unwrap_or(d);
            if first_para.len() > 500 {
                format!("{}...", &first_para[..497])
            } else {
                first_para.to_string()
            }
        });

        // Capture MITRE-declared required data sources verbatim. The STIX
        // bundle uses labels like "Process: Process Creation" which the
        // coverage API later maps to nanosiem source_type identifiers.
        let data_sources = obj.x_mitre_data_sources.clone().unwrap_or_default();

        Some(MitreTechnique {
            id: external_id,
            name: name.clone(),
            description,
            url,
            is_subtechnique,
            parent_id,
            tactic_ids,
            deprecated: false,
            data_sources,
        })
    }

    /// Check if sync is needed (no data or data is older than 7 days)
    pub async fn needs_sync(&self) -> Result<bool, sqlx::Error> {
        if !self.repository.has_data().await? {
            return Ok(true);
        }

        if let Some(metadata) = self.repository.get_sync_metadata().await? {
            let age = chrono::Utc::now() - metadata.last_sync_at;
            return Ok(age.num_days() > 7);
        }

        Ok(true)
    }
}

-- Sync enabled flags from marketplace_catalog to underlying enrichment sources.
-- Fixes a bug where the marketplace configure endpoint only updated
-- marketplace_catalog.enabled without propagating to enrichment_sources,
-- identity_providers, or custom_enrichments.

UPDATE enrichment_sources es
SET enabled = mc.enabled, updated_at = NOW()
FROM marketplace_catalog mc
WHERE mc.native_source_id = es.id
  AND mc.installed = true
  AND mc.enabled IS NOT NULL
  AND mc.enabled != es.enabled;

UPDATE identity_providers ip
SET enabled = mc.enabled
FROM marketplace_catalog mc
WHERE mc.identity_provider_id = ip.id
  AND mc.installed = true
  AND mc.enabled IS NOT NULL
  AND mc.enabled != ip.enabled;

UPDATE custom_enrichments ce
SET enabled = mc.enabled
FROM marketplace_catalog mc
WHERE mc.custom_enrichment_id = ce.id
  AND mc.installed = true
  AND mc.enabled IS NOT NULL
  AND mc.enabled != ce.enabled;

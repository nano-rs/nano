-- NAN-1124: per-source deprovisioned-count for the Ingestion Marketplace cards.
-- Populated by the push deprovisioning reconcile job (NAN-1134) for push sources
-- and by identity-sync mark-absent for pull/identity providers. Additive and
-- idempotent. Runs on BOTH the enterprise path (001_init / 100_identity_providers)
-- and the open-core path (postgres-open/000_open_init snapshot), since both apply
-- the numbered postgres/ migrations after their respective baseline — so this one
-- ALTER covers every deployment without editing any applied/init migration.
ALTER TABLE identity_providers
    ADD COLUMN IF NOT EXISTS deprovisioned_count BIGINT NOT NULL DEFAULT 0;

ALTER TABLE enrichment_sources
    ADD COLUMN IF NOT EXISTS deprovisioned_count BIGINT NOT NULL DEFAULT 0;

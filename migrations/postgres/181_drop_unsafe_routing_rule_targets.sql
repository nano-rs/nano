-- NAN-858: drop routing_rules whose target_source_type contains characters
-- outside the safe allow-list ([A-Za-z0-9_-]).
--
-- Background: migration 177 seeded the Vector Ingestion config with a default
-- rule whose target_source_type = '${source_type}' — an internal VRL
-- passthrough sentinel that was never meant to live in DB. It leaked into
-- the rollup IN-clause builder (`GET /api/source-configurations` → rollup
-- query) and fired a WARN on every list request. The rule is also
-- functionally redundant: Vector Ingestion still works through the
-- unconditional `vector_merge` base router input; the seeded rule's only
-- effect was to mark "Vector default = passthrough" in DB, which is already
-- the implicit behavior for system_level configs with no rules.
--
-- Write-time validation now rejects unsafe target values at create/update.
-- This migration cleans up the existing seeded row and any past-leaked rows.
DELETE FROM routing_rules
WHERE target_source_type !~ '^[A-Za-z0-9_-]+$';

-- NAN-1923: make the alias map part of "is the catalog current?".
--
-- NAN-1918 hangs the alias write, the mapping repair and the non-destructive
-- reconcile off `replace_catalog_on`. But `MitreSync::run_locked` short-circuits
-- on `catalog_is_current_on` before it ever gets there, and that check only
-- compares release version, source digest and tactic/technique counts — all of
-- which already match on a tenant that synced v19.1.
--
-- That is exactly the damaged population: every tenant whose mappings were
-- destroyed on 2026-07-11 is, by definition, already on v19.1. So the repair
-- was unreachable until the next ATT&CK release moved the pin.
--
-- Recording the alias count here lets the currency check notice a tenant that
-- has the catalog but not the alias map. Existing rows have NULL, which never
-- equals a count, so each tenant runs exactly one catch-up sync and is current
-- again afterwards. A release that legitimately ships zero revoked-by edges
-- records 0 and matches 0 — a bare EXISTS test would instead re-fetch the
-- 51 MB bundle on every scheduler tick forever.

ALTER TABLE public.mitre_sync_state
    ADD COLUMN IF NOT EXISTS alias_count INTEGER;

COMMENT ON COLUMN public.mitre_sync_state.alias_count IS
    'Number of technique aliases written by the last successful sync. NULL means the sync predates NAN-1918, so the alias map is missing and one catch-up sync is owed.';

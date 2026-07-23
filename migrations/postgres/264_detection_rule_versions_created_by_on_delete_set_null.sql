-- NAN-2026: detection_rule_versions.created_by referenced users(id) with the
-- default NO ACTION, so deleting ANY user who had authored/promoted a rule
-- version failed with a foreign-key violation. This surfaced as demo-session
-- teardown failing every cycle ("update or delete on table users violates
-- foreign key constraint detection_rule_versions_created_by_fkey"), but it is a
-- latent bug for real user deletion too.
--
-- ON DELETE SET NULL (matching the api_keys_created_by_fkey / audit-actor
-- pattern already used across the schema) preserves the rule version/audit
-- history and only detaches the deleted author. created_by is already nullable
-- and the code binds Option<Uuid>, so nothing else changes. CASCADE would be
-- wrong here — it would delete version history (including on rules owned by
-- other users) when a user is removed.
ALTER TABLE public.detection_rule_versions
    DROP CONSTRAINT IF EXISTS detection_rule_versions_created_by_fkey;

ALTER TABLE public.detection_rule_versions
    ADD CONSTRAINT detection_rule_versions_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;

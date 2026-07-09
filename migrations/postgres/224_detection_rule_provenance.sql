-- NAN-1764: Detection-as-Code rule provenance.
--
-- Records where a rule's file lives in a customer's detection-as-code repo so
-- that AI tuning PRs (NAN-1745) target the *exact* file the rule came from,
-- instead of a name-templated path that duplicates the rule when the customer's
-- repo layout differs from `path_template`.
--
-- NULL on both columns = a nano-native rule (created in the UI, not git-managed).
-- The columns are populated by the DaC pipeline (nanodac) when it imports a rule
-- via the rule create/update API; nano never derives them.

ALTER TABLE detection_rules
    ADD COLUMN IF NOT EXISTS source_path TEXT,
    ADD COLUMN IF NOT EXISTS source_repo_url TEXT;

COMMENT ON COLUMN detection_rules.source_path IS
    'Path of this rule''s file within its detection-as-code repo (NULL = nano-native, not git-managed). Tuning PRs target this exact path when set (NAN-1764).';
COMMENT ON COLUMN detection_rules.source_repo_url IS
    'Repo URL this rule was imported from (NULL = nano-native). Informational in v1; the push target is tenant-wide (NAN-1764).';

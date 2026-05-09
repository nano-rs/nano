-- NAN-730: per-folder display settings (icon, etc.) for the rule editor.
--
-- Folders themselves are derived from `detection_rules.folder` (no separate
-- folders table — keeps the namespace flat and self-cleaning). This table
-- stores presentation metadata keyed by folder name. Rows are optional:
-- folders without a row fall back to the frontend's default icon mapping
-- (canonical Network/Identity/Endpoint/Cloud icons + generic Folder for
-- everything else).
--
-- The PRIMARY KEY constraint mirrors the folder-name validator at
-- nanosiem-core/src/models/detection_rule.rs:564 (alphanumeric + dash +
-- underscore, ≤ 50 chars). Application-level enforcement is the source of
-- truth; the column constraint here is just a width guard.

CREATE TABLE folder_settings (
    name        VARCHAR(50) PRIMARY KEY,
    icon        VARCHAR(40) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE folder_settings IS
    'Per-folder display settings (icon) for detection-rule folders. Rows optional.';

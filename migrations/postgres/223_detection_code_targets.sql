-- Detection-as-Code Push Target (NAN-1745)
-- Lets a customer register THEIR detection-as-code repo as a write destination so
-- AI tuning can open a Pull Request there for review instead of mutating
-- detection_rules directly. Push-only: nano never pulls rules from this repo.
-- Distinct from rule_repositories (a public, unauthenticated PULL feed that
-- deliberately stores no auth token). Here we DO store a fine-grained GitHub PAT,
-- AES-256-GCM-encrypted, mirroring the cloud_credentials (BYTEA ciphertext,
-- VARCHAR nonce) pattern from migration 007.

-- =============================================================================
-- Push Target Table
-- =============================================================================

CREATE TABLE IF NOT EXISTS detection_code_targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    repo_url TEXT NOT NULL,                                      -- https://github.com/org/repo
    base_branch TEXT NOT NULL DEFAULT 'main',                   -- PR base branch
    path_template TEXT NOT NULL DEFAULT 'detections/{rule_name}.yaml',
    pr_branch_prefix TEXT NOT NULL DEFAULT 'nano-tuning/',
    rule_format TEXT NOT NULL DEFAULT 'nanosiem',               -- 'nanosiem' (nPL) | 'sigma' (future)
    -- Encrypted fine-grained PAT (Contents + Pull requests: write), AES-256-GCM.
    -- token_encrypted is the raw ciphertext bytes; token_nonce is the base64 nonce.
    -- NULL until a token is set via the write-only token endpoint.
    token_encrypted BYTEA,
    token_nonce VARCHAR(32),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_pr_url TEXT,
    last_pr_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT detection_code_targets_format_check CHECK (rule_format IN ('nanosiem', 'sigma'))
);

COMMENT ON TABLE detection_code_targets IS 'Customer detection-as-code repos that AI tuning opens PRs into (push-only, NAN-1745)';
COMMENT ON COLUMN detection_code_targets.repo_url IS 'GitHub repo URL the tuning PR is opened against (github.com only in v1)';
COMMENT ON COLUMN detection_code_targets.path_template IS 'File path template within the repo; {rule_name} substituted per rule';
COMMENT ON COLUMN detection_code_targets.pr_branch_prefix IS 'Prefix for the head branch created per tuning PR';
COMMENT ON COLUMN detection_code_targets.token_encrypted IS 'AES-256-GCM ciphertext (BYTEA) of the GitHub PAT; NULL until configured';
COMMENT ON COLUMN detection_code_targets.token_nonce IS 'Base64-encoded 12-byte nonce for token_encrypted';

CREATE INDEX IF NOT EXISTS idx_detection_code_targets_enabled
    ON detection_code_targets(enabled) WHERE enabled = TRUE;

-- NOTE (NAN-1757): the enterprise-only PR columns + pr_opened status for the
-- tuning proposals table live in the enterprise migration set
-- (9000025_tuning_proposals_pr_columns.sql), NOT here. That table is absent from
-- the open-init snapshot (it is created by the enterprise overlay 9000002), so
-- touching it from this core migration would break fresh open installs.
-- (Wording kept keyword-free on purpose so the snapshot-drift guard test in
-- db/migrations.rs doesn't read a table reference out of this comment.)

-- =============================================================================
-- Permissions
-- =============================================================================

INSERT INTO permissions (id, name, description, category) VALUES
    ('detection_code_targets:view', 'View Detection-as-Code Targets', 'View configured detection-as-code push targets', 'detection'),
    ('detection_code_targets:manage', 'Manage Detection-as-Code Targets', 'Connect, edit, and delete detection-as-code push targets and their credentials', 'detection')
ON CONFLICT (id) DO NOTHING;

-- Grant both to the Admin role (credential-bearing surface — admin only).
INSERT INTO role_permissions (role_id, permission_id)
SELECT
    '00000000-0000-0000-0000-000000000001'::uuid,  -- Admin role
    id
FROM permissions
WHERE id LIKE 'detection_code_targets:%'
ON CONFLICT DO NOTHING;

-- =============================================================================
-- Updated timestamp trigger
-- =============================================================================

CREATE OR REPLACE FUNCTION update_detection_code_target_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_detection_code_targets_timestamp
    BEFORE UPDATE ON detection_code_targets
    FOR EACH ROW
    EXECUTE FUNCTION update_detection_code_target_timestamp();

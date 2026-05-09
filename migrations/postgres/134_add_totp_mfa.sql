-- TOTP MFA support for local (non-SSO) users
-- Supports both user-optional enrollment and admin-enforced enrollment

-- MFA columns on users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret_encrypted BYTEA;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret_nonce VARCHAR(32);
ALTER TABLE users ADD COLUMN IF NOT EXISTS backup_codes_encrypted BYTEA;
ALTER TABLE users ADD COLUMN IF NOT EXISTS backup_codes_nonce VARCHAR(32);
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_setup_pending BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN users.mfa_enabled IS 'Whether TOTP MFA is active for this user';
COMMENT ON COLUMN users.totp_secret_encrypted IS 'AES-256-GCM encrypted TOTP secret (base32)';
COMMENT ON COLUMN users.totp_secret_nonce IS 'Base64-encoded nonce for TOTP secret decryption';
COMMENT ON COLUMN users.backup_codes_encrypted IS 'AES-256-GCM encrypted JSON array of bcrypt-hashed backup codes';
COMMENT ON COLUMN users.backup_codes_nonce IS 'Base64-encoded nonce for backup codes decryption';
COMMENT ON COLUMN users.mfa_setup_pending IS 'True when admin enforced MFA but user has not completed setup';

-- System-wide MFA enforcement setting
ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS mfa_required BOOLEAN NOT NULL DEFAULT FALSE;
COMMENT ON COLUMN system_settings.mfa_required IS 'When true, all local (non-OIDC) users must enroll in TOTP MFA';

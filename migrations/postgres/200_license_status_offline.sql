-- NAN-1206 (WS4): offline / air-gapped license import.
--
-- Air-gapped deployments import a signed license bundle (no network check-in).
-- This `offline` flag records that the cached license_status row was set by an
-- operator-imported bundle rather than by the periodic LicenseChecker. Code
-- that ages out a license for lack of a heartbeat MUST treat offline = TRUE as
-- exempt from staleness (the air-gapped install has no license server to reach).
--
-- Default FALSE so existing/online deployments are unchanged.

ALTER TABLE license_status
    ADD COLUMN IF NOT EXISTS offline BOOLEAN NOT NULL DEFAULT FALSE;

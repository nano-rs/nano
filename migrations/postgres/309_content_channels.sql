-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-4955: nano content channels. Every first-party content pull (parsers,
-- rules, playbooks, marketplace catalog, model catalog, extension catalogs) comes
-- from the app as a signed content bundle (nanosiem-core content_bundle);
-- no install fetches content from GitHub.
--
-- content_channel_state: one row per channel (registry id, e.g.
--   `parsers.main`). Holds the LAST GOOD install (the verified signed
--   descriptor is the rollback reference for the next one), the operator's
--   opt-out (`enabled`), and the latest check. A refused or failed check only
--   touches the last_* columns; the installed snapshot stays.
-- content_channel_files: the verified files of each channel's installed
--   snapshot (git blob SHA-1 ids, the same ids the GitHub tree API reported,
--   so an upgraded install sees no spurious change). First-party repository
--   syncs read these rows instead of the network. Replaced in ONE transaction
--   per install, together with the state row.
--
-- Additive only; nothing existing is altered. Forward-only and idempotent.

CREATE TABLE IF NOT EXISTS content_channel_state (
    channel TEXT PRIMARY KEY CHECK (channel ~ '^[a-z0-9][a-z0-9.-]{0,63}$'),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    signed_descriptor JSONB,
    sequence BIGINT,
    upstream_commit TEXT,
    tree_sha256 TEXT,
    file_count INTEGER,
    source TEXT CHECK (source IS NULL OR source IN ('online', 'offline')),
    route TEXT CHECK (route IS NULL OR route IN ('open', 'enterprise', 'mirror', 'file')),
    installed_at TIMESTAMPTZ,
    applied_at TIMESTAMPTZ,
    apply_error TEXT,
    last_check_at TIMESTAMPTZ,
    last_check_status TEXT,
    last_error TEXT,
    last_error_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE content_channel_state IS
    'NAN-4955: last good install of each signed nano content channel bundle, the operator opt-out, and the latest check.';

CREATE TABLE IF NOT EXISTS content_channel_files (
    channel TEXT NOT NULL REFERENCES content_channel_state(channel) ON DELETE CASCADE,
    path TEXT NOT NULL,
    blob_sha1 TEXT NOT NULL CHECK (blob_sha1 ~ '^[0-9a-f]{40}$'),
    size BIGINT NOT NULL CHECK (size >= 0),
    content BYTEA NOT NULL,
    PRIMARY KEY (channel, path)
);

COMMENT ON TABLE content_channel_files IS
    'NAN-4955: verified files of each installed content channel snapshot; first-party repository syncs read these instead of GitHub.';

-- NAN-3807: OCSF bucket drop (open core). A sender that already maps to
-- OCSF 1.9 (Tenzir) writes files straight into the install's object store
-- under `landing-ocsf-v1/tenant_id=<T>/source=<source_id>/`. The landing
-- converter (`lake_landing_ingest`) turns each file into one ordinary bronze
-- object, so part ingest admits and enriches it exactly like Vector's files.
--
-- landing_sources: one row per bucket-drop source. The folder decides the
-- source (NAN-3806: the credential decides, never the rows). `source_id` is
-- the log source; its write-only object-store user (`object_user`) may put
-- objects under that source's folder only. Revoking deletes the user.
-- The key itself is never stored.
--
-- landing_files: the listed-and-claimed ledger. Every object seen under the
-- landing prefix is claimed once per (object_key, etag) with
-- INSERT ... ON CONFLICT DO NOTHING, so a late or out-of-order key is still
-- picked up (no time watermark). A claim carries a lease; a converter that
-- dies mid-file leaves an expired lease, and the next tick re-claims it.
-- Reconversion is safe: rows keep the sender's metadata.uid, and rows without
-- one get a uid derived from the file's content hash and row ordinal, so the
-- lake's uid window drops the repeat. `reason` is a value-free code.
--
-- No foreign key to log_sources: core migrations also run on hosted
-- databases, where 9000321 made log_sources' identity tenant-first
-- ((tenant_id, id)) and its FK-closure check refuses a child without a
-- tenant column. Integrity is kept by the converter instead: a landing source
-- whose log source is gone accepts no file, and every tick revokes it (deletes
-- its object-store user and policy, then the row).
--
-- Additive and idempotent.

CREATE TABLE IF NOT EXISTS landing_sources (
    source_id UUID PRIMARY KEY,
    route_key TEXT NOT NULL CHECK (route_key ~ '^[a-z0-9][a-z0-9_]{0,99}$'),
    credential_id UUID NOT NULL UNIQUE,
    object_user TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked')),
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS landing_files (
    id BIGSERIAL PRIMARY KEY,
    object_key TEXT NOT NULL,
    etag TEXT NOT NULL,
    -- NULL when the key is not under a known source folder.
    source_id UUID REFERENCES landing_sources(source_id) ON DELETE SET NULL,
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    state TEXT NOT NULL CHECK (state IN ('claimed', 'accepted', 'refused')),
    rows_accepted BIGINT NOT NULL DEFAULT 0 CHECK (rows_accepted >= 0),
    rows_refused BIGINT NOT NULL DEFAULT 0 CHECK (rows_refused >= 0),
    reason TEXT CHECK (reason IS NULL OR reason ~ '^[a-z0-9_]{1,64}$'),
    content_sha256 TEXT CHECK (content_sha256 IS NULL OR content_sha256 ~ '^[0-9a-f]{64}$'),
    bronze_key TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    -- The same (object_key, etag) written again after it finished: deleted
    -- without reconverting (its rows are already in the lake).
    redeliveries INTEGER NOT NULL DEFAULT 0,
    lease_until TIMESTAMPTZ,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    UNIQUE (object_key, etag)
);

CREATE INDEX IF NOT EXISTS idx_landing_files_source_finished
    ON landing_files (source_id, finished_at DESC);
CREATE INDEX IF NOT EXISTS idx_landing_files_claimed
    ON landing_files (lease_until) WHERE state = 'claimed';

-- NAN-4629: OCSF bucket drop (364) run active-active by several converter
-- nodes (sovereign `--tenzir`, N >= 4), possibly for several tenants on one
-- database (an MSSP sovereign install).
--
-- 1. tenant_id on both ledger tables. A converter is bound to one tenant and
--    every ledger read and write it makes is filtered by it: it never claims,
--    finishes or even sees another tenant's file or source. The tenant of a
--    file is the folder in its key (`landing-ocsf-v1/tenant_id=<T>/...`); the
--    tenant of a source is recorded when the source is added and must match
--    the folder its files land in, or the files are refused (source_unknown).
--    Rows written before this migration have NULL and are adopted by their
--    install's converter (files by their key's folder; sources only while
--    the install has a single tenant).
--
-- 2. One lister per tenant. Listing the landing folder costs a LIST per page
--    on the object store (billed per request on BYO S3), so only the holder
--    of the tenant's `landing_listers` lease lists. It records every object as
--    a 'listed' ledger row; every node then claims from the ledger, never from
--    a listing of its own. A lister that dies stops renewing; another node
--    takes the lease once it expires.
--
-- 3. landed_at: the object's Last-Modified, for the backlog-age health field
--    (oldest unfinished landed file).
--
-- 4. refused_in_place: a refused file no copy could be kept of (sovereign:
--    empty, or over the consumer store's 64 MiB write bound) stays where it
--    landed and is never deleted. Its row is never claimed or treated as a
--    redelivery again, and is not pruned while it exists.
--
-- Additive and idempotent. Open core (one converter, one tenant) behaves as
-- before: its converter holds the lease and claims what it listed.

ALTER TABLE landing_sources ADD COLUMN IF NOT EXISTS tenant_id TEXT;
ALTER TABLE landing_files ADD COLUMN IF NOT EXISTS tenant_id TEXT;
ALTER TABLE landing_files ADD COLUMN IF NOT EXISTS landed_at TIMESTAMPTZ;
ALTER TABLE landing_files ADD COLUMN IF NOT EXISTS refused_in_place BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE landing_files DROP CONSTRAINT IF EXISTS landing_files_state_check;
ALTER TABLE landing_files
    ADD CONSTRAINT landing_files_state_check CHECK (state IN ('listed', 'claimed', 'accepted', 'refused'));

-- The claim queue: a tenant's unfinished rows in landing order.
CREATE INDEX IF NOT EXISTS idx_landing_files_tenant_open
    ON landing_files (tenant_id, id) WHERE state IN ('listed', 'claimed');
CREATE INDEX IF NOT EXISTS idx_landing_sources_tenant
    ON landing_sources (tenant_id, source_id);

CREATE TABLE IF NOT EXISTS landing_listers (
    tenant_id TEXT PRIMARY KEY,
    -- The converter node holding the lease (a random id per process).
    holder UUID NOT NULL,
    lease_until TIMESTAMPTZ NOT NULL,
    listed_at TIMESTAMPTZ
);

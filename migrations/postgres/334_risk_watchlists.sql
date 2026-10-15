-- NAN-3228: risk watchlists — named, weighted groups of risk entities.
--
-- A watchlist amplifies its members' accumulated risk at READ time:
-- effective = base x (1 + weight), weight in [0, 1]. Paused lists
-- (enabled = FALSE) apply nothing; an entity on several enabled lists takes
-- the MAX weight (no compounding). Nothing is rewritten in the findings
-- ledger, so pausing or deleting a list takes effect on the next read.
--
-- Members match risk entities by their normalized (trimmed, lowercased)
-- VALUE, the same key the clear boundaries use; `entity_type` is the
-- analyst's classification for display and filtering.
--
-- Bounds (enforced by the API, documented here): at most 50 lists per
-- tenant, 500 members per list and 2000 member rows per tenant, so the
-- weight map every risk read carries stays small.
--
-- Tables are tenant-keyed (tenant-first keys) so the enterprise overlay
-- (9011350) can register them for RLS on hosted-shared. Dedicated binds the
-- compatibility tenant explicitly.
CREATE TABLE IF NOT EXISTS risk_watchlists (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    name TEXT NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9_]{0,63}$'),
    description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 200),
    weight NUMERIC(3, 2) NOT NULL DEFAULT 0.50 CHECK (weight >= 0 AND weight <= 1),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    owner_id UUID,
    owner_label TEXT NOT NULL DEFAULT '' CHECK (length(owner_label) <= 256),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    review_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT risk_watchlists_tenant_name UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS risk_watchlist_members (
    tenant_id UUID NOT NULL,
    watchlist_id UUID NOT NULL,
    entity_type TEXT NOT NULL CHECK (entity_type IN ('user', 'host', 'ip', 'hash')),
    entity_value TEXT NOT NULL CHECK (
        length(entity_value) BETWEEN 1 AND 1024 AND entity_value = lower(btrim(entity_value))
    ),
    note TEXT NOT NULL DEFAULT '' CHECK (length(note) <= 500),
    added_by TEXT NOT NULL DEFAULT '' CHECK (length(added_by) <= 256),
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, watchlist_id, entity_type, entity_value),
    FOREIGN KEY (tenant_id, watchlist_id)
        REFERENCES risk_watchlists (tenant_id, id) ON DELETE CASCADE
);

-- Lookup by entity ("which lists is this entity on?") and the weight map.
CREATE INDEX IF NOT EXISTS idx_risk_watchlist_members_entity
    ON risk_watchlist_members (tenant_id, entity_value);

COMMENT ON TABLE risk_watchlists IS
    'NAN-3228: weighted risk watchlists. effective risk = base x (1 + weight) for members of enabled lists (max weight across lists). Applied at read time; nothing in the findings ledger is rewritten.';
COMMENT ON TABLE risk_watchlist_members IS
    'NAN-3228: watchlist members keyed by normalized (lowercased) entity value; entity_type is the analyst classification.';

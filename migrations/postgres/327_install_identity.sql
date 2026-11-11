-- NAN-5249: a random identifier for this install.
--
-- A Self-run licence covers two installs (production plus one for dev, DR or
-- backup). nano-main tells installs apart by this ID: it rides on the licence
-- check-in and the daily usage report as the `X-Nano-Install-Id` header.
--
-- One row per PostgreSQL database. Every app host of an HA cluster shares the
-- database, so the whole cluster is one install. The row is created here, once,
-- while the one-shot migrator holds its lock; `InstallIdentityRepository`
-- re-creates it idempotently (INSERT ... ON CONFLICT DO NOTHING, then SELECT)
-- if it is ever missing, so concurrent hosts still agree on one ID.
--
-- The ID is random and carries nothing about the install. Restoring a database
-- backup elsewhere copies it; that copy counts as the same install.
--
-- Forward-only and idempotent.

CREATE TABLE IF NOT EXISTS install_identity (
    -- Singleton row.
    id          BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    -- Sent on the wire as the TypeID `inst_<base32>`.
    install_id  UUID NOT NULL DEFAULT gen_random_uuid(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO install_identity (id) VALUES (TRUE) ON CONFLICT (id) DO NOTHING;

-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-5903: the pull feed setup lease.
--
-- Starting a pull feed onto lanes that lack a log source sets those sources
-- up (create or widen, deploy, check, start the feed). One start at a time
-- runs under a lease row here, claimed atomically (insert, or take over an
-- EXPIRED row), renewed while a long deploy runs and deleted on release. A
-- holder that dies leaves a row that lapses at expires_at. No database
-- connection is held while a lease is held. `generation` is bumped on every
-- claim: (owner, generation) is the holder's fencing token, which every
-- setup write is conditioned on, so a holder whose lease lapsed and was taken
-- over cannot change anything. Forward-only and idempotent.
CREATE TABLE IF NOT EXISTS connector_feed_setup_leases (
    key TEXT PRIMARY KEY,
    owner UUID NOT NULL,
    purpose TEXT NOT NULL DEFAULT '',
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    generation BIGINT NOT NULL DEFAULT 1
);

COMMENT ON TABLE connector_feed_setup_leases IS
    'NAN-5903: lease serializing pull feed starts that set up lane log sources (one row per lease key; expired rows are taken over)';

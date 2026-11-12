-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-5285 (v2.0.13 retest F3): one ingest host installs a new Vector config
-- generation at a time.
--
-- Every ingest host's config consumer polls the same API and used to install
-- (reload Vector) the moment a generation was published, so a log-source
-- deploy stalled ingest on the whole cluster at once. A consumer now takes
-- this lease before it installs, drains its host from the load balancer
-- (readiness withdrawn), installs, rejoins, then releases the lease.
--
-- One row per scope ('ingest'). `expires_at` bounds a holder that died
-- mid-install: the next consumer takes the lease over once it has expired.
-- The row lives in PostgreSQL so every app host answers for the same lease.
CREATE TABLE IF NOT EXISTS public.vector_config_install_leases (
    scope       TEXT PRIMARY KEY,
    holder      TEXT NOT NULL,
    generation  BIGINT NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);

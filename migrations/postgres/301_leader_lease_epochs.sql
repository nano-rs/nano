-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-4933 (L9, G21): jobs warm-standby lease epochs.
--
-- The jobs leader holds a PostgreSQL advisory lock (a lease: renew 2 s,
-- self-fence within 5 s, a stale holder is evicted after 20 s). Every
-- acquisition bumps leader_lease_epochs.epoch on the lock session BEFORE any
-- leader-only task starts. Leader-only writes check that epoch (tick gate) or
-- take FOR SHARE on its row inside their own transaction (strict guard), so a
-- leader that was frozen past its eviction and then resumes cannot write
-- after its successor started. leader_lease_history keeps one row per epoch
-- (who led, from when) for operators and for the takeover drill.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS public.leader_lease_epochs (
    lock_id     BIGINT PRIMARY KEY,
    epoch       BIGINT NOT NULL CONSTRAINT leader_lease_epochs_epoch_positive CHECK (epoch > 0),
    holder      TEXT NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.leader_lease_history (
    id          BIGSERIAL PRIMARY KEY,
    lock_id     BIGINT NOT NULL,
    epoch       BIGINT NOT NULL,
    holder      TEXT NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT leader_lease_history_epoch_unique UNIQUE (lock_id, epoch)
);

-- Which lease epoch ran each scheduled credential re-wrap (migration 300).
ALTER TABLE public.credential_key_rewrap_runs
    ADD COLUMN IF NOT EXISTS leader_epoch BIGINT;

COMMENT ON TABLE public.leader_lease_epochs IS
    'Current lease epoch per leader lock; bumped by the lock holder at each acquisition and checked by leader-only writes (NAN-4933)';
COMMENT ON TABLE public.leader_lease_history IS
    'One row per leader lease epoch: holder and acquisition time (NAN-4933)';

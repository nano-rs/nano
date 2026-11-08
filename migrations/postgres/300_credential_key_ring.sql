-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-4933 (L9): credential key ring bookkeeping for online rotation.
--
-- Key material NEVER lives here: only ids and a one-way fingerprint
-- (HMAC-SHA256 of the root over a fixed domain, truncated), which detects an
-- id reused for different material.
--
-- credential_keys              every ring key any process has loaded; retire
--                              state and the last scan's "values still on this
--                              key" count (the visible rotation backlog).
-- credential_key_ring_members  which process (api / jobs node) holds which
--                              active key, so a key that some live process
--                              still writes with can never be retired.
-- credential_key_rewrap_runs   history of re-wrap passes (scheduled, boot,
--                              manual) with their counts.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS public.credential_keys (
    key_id          TEXT PRIMARY KEY
                    CONSTRAINT credential_keys_key_id_format CHECK (key_id ~ '^[A-Za-z0-9._-]{1,64}$'),
    fingerprint     TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'in_use'
                    CONSTRAINT credential_keys_state_check CHECK (state IN ('in_use', 'retired')),
    referenced_rows BIGINT,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_active_at  TIMESTAMPTZ,
    last_scanned_at TIMESTAMPTZ,
    retired_at      TIMESTAMPTZ,
    retired_by      UUID
);

CREATE TABLE IF NOT EXISTS public.credential_key_ring_members (
    node_id       TEXT PRIMARY KEY,
    service       TEXT NOT NULL,
    active_key_id TEXT NOT NULL,
    key_ids       TEXT[] NOT NULL,
    seen_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.credential_key_rewrap_runs (
    id            BIGSERIAL PRIMARY KEY,
    trigger       TEXT NOT NULL
                  CONSTRAINT credential_key_rewrap_runs_trigger_check CHECK (trigger IN ('boot', 'scheduled', 'manual')),
    node_id       TEXT NOT NULL,
    active_key_id TEXT NOT NULL,
    started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at   TIMESTAMPTZ,
    scanned       BIGINT NOT NULL DEFAULT 0,
    rewrapped     BIGINT NOT NULL DEFAULT 0,
    conflicts     BIGINT NOT NULL DEFAULT 0,
    undecryptable BIGINT NOT NULL DEFAULT 0,
    per_key       JSONB,
    error         TEXT
);

CREATE INDEX IF NOT EXISTS credential_key_rewrap_runs_started_idx
    ON public.credential_key_rewrap_runs (started_at DESC);

COMMENT ON TABLE public.credential_keys IS
    'Credential key ring ids + one-way fingerprints (never key material); retire state and last re-wrap scan counts (NAN-4933)';
COMMENT ON TABLE public.credential_key_ring_members IS
    'Which process holds which active credential key; a key a live process writes with cannot be retired (NAN-4933)';
COMMENT ON TABLE public.credential_key_rewrap_runs IS
    'Credential re-wrap pass history (NAN-4933)';

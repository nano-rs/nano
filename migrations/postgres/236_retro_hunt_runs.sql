-- NAN-1791: retro-hunt run history.
--
-- One row per execution of a retro-hunt rule, so the UI can show WHAT each run
-- did: how many candidate indicators it considered, how many it actually hunted,
-- how many were found in logs (hits), and — critically — whether the per-run cap
-- TRUNCATED the batch (with the remaining overflow carried to the next run). No
-- silent caps: truncation is recorded here and surfaced in the rule's run
-- history.

CREATE TABLE IF NOT EXISTS retro_hunt_runs (
    id                      BIGSERIAL PRIMARY KEY,
    rule_id                 UUID        NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    started_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at             TIMESTAMPTZ,
    -- 'running' | 'ok' | 'error'
    status                  TEXT        NOT NULL DEFAULT 'running',
    -- Distinct candidate indicators the run considered (post feed/type/watermark
    -- filter, pre per-run cap).
    candidates_considered   INT         NOT NULL DEFAULT 0,
    -- Indicators actually handed to the retro engine this run (<= cap).
    indicators_hunted       INT         NOT NULL DEFAULT 0,
    -- Indicators found in historical logs (emitted as signals/alerts).
    hits                    INT         NOT NULL DEFAULT 0,
    -- The per-run cap truncated the batch; overflow_remaining were carried over.
    truncated               BOOLEAN     NOT NULL DEFAULT FALSE,
    overflow_remaining      INT         NOT NULL DEFAULT 0,
    watermark_before        TIMESTAMPTZ,
    watermark_after         TIMESTAMPTZ,
    error                   TEXT
);

CREATE INDEX IF NOT EXISTS idx_retro_hunt_runs_rule
    ON retro_hunt_runs (rule_id, started_at DESC);
